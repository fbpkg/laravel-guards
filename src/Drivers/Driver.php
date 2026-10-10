<?php

namespace Fbpkg\Guards\Drivers;

use Fbpkg\Guards\Contracts\Driver as DriverContract;
use Fbpkg\Guards\Exceptions\AuthenticationException;
use Fbpkg\Guards\Models\AuthSession;
use Fbpkg\Guards\Providers\Provider;
use Fbpkg\Guards\Sources\Source;
use Fbpkg\Guards\Support\Jwt;
use Fbpkg\Guards\Types\Config\Guard as GuardConfig;
use Fbpkg\Guards\Types\SessionCredentials;
use Fbpkg\Guards\Types\SessionValidation;
use Illuminate\Database\Eloquent\Model;
use JsonException;
use UnexpectedValueException;

/**
 * Handles authentication and authentication-session lifecycle operations.
 *
 * Session and JWT drivers share the same persistence and refresh lifecycle.
 * They differ only in how access credentials are issued and resolved.
 */
class Driver implements DriverContract
{
    /**
     * The cached authentication session to avoid repeated database queries.
     */
    protected ?AuthSession $session = null;

    public function __construct(
        protected string $guard,
        protected GuardConfig $config,
        protected Provider $provider,
        protected Source $source,
    ) {}

    /**
     * Retrieve the authenticated entity for the current request.
     *
     * Automatically refreshes expired access credentials when the current
     * session is refreshable and the credential source uses cookies.
     *
     * Returns null when no valid authentication session is available or
     * when automatic refresh is not applicable.
     *
     * @return Model|null The authenticated entity, or null if unauthenticated.
     *
     * @throws AuthenticationException If automatic refresh fails.
     */
    public function authenticatable(): ?Model
    {
        $session = $this->authenticatedSession();
        $validation = $this->validateSession($session);

        if ($validation->isAuthenticated()) {
            return $this->resolveAuthenticatable($session);
        }

        if (
            !$validation->isRefreshable()
            || !$this->source->isCookieSource()
        ) {
            return null;
        }

        $this->refresh();

        $session = $this->authenticatedSession();

        return $this->resolveAuthenticatable($session);
    }

    /**
     * Retrieve the claims from the current JWT access token.
     *
     * Returns null when the configured driver is not JWT or the access
     * token is missing or invalid.
     *
     * @return array<string, mixed>|null The JWT claims, or null if unavailable.
     */
    public function jwtClaims(): ?array
    {
        if ($this->config->driver !== 'jwt') {
            return null;
        }

        $access = $this->source->access();

        if ($access === null || $access === '') {
            return null;
        }

        return $this->decodeJwt($access);
    }

    /**
     * Authenticate the given entity and issue session credentials.
     *
     * @param Model $authenticatable The entity to authenticate.
     * @param bool $remember Whether to issue a refresh credential.
     *
     * @return SessionCredentials The issued access and refresh credentials.
     */
    public function login(
        Model $authenticatable,
        bool $remember = false,
    ): SessionCredentials {
        $now = now();
        $accessToken = $this->generateToken();
        $refreshToken = $remember ? $this->generateToken() : null;

        $accessCredential = match ($this->config->driver) {
            'session' => $accessToken,
            'jwt' => $this->createJwt($authenticatable, $accessToken),
        };

        $session = [
            'authenticatable_id' => $authenticatable->getKey(),
            'guard' => $this->guard,
            'access_token_hash' => $this->hashToken($accessToken),
            'access_expires_at' => $now->copy()->addSeconds(
                $this->config->accessLifetime,
            ),
            'ip_address' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'created_at' => $now,
            'last_used_at' => $now,
        ];

        if ($refreshToken !== null) {
            $session['refresh_token_hash'] = $this->hashToken($refreshToken);
            $session['refresh_expires_at'] = $now->copy()->addSeconds(
                $this->config->refreshLifetime,
            );
        }

        $this->session = AuthSession::query()->create($session);

        $credentials = new SessionCredentials(
            access: $accessCredential,
            refresh: $refreshToken,
        );

        $this->source->store($credentials);

        return $credentials;
    }

    /**
     * Refresh the current authentication credentials.
     *
     * Refresh rotation replaces the refresh credential when enabled.
     * A rolling refresh policy also renews its expiry.
     *
     * @return SessionCredentials The renewed credentials.
     *
     * @throws AuthenticationException If the refresh credential is missing,
     *     invalid, or expired, or the authenticatable cannot be found.
     */
    public function refresh(): SessionCredentials
    {
        $refreshToken = $this->source->refresh();

        if ($refreshToken === null || $refreshToken === '') {
            throw AuthenticationException::missingRefreshCredential();
        }

        $session = $this->authenticatedSession(
            credential: 'refresh',
            fresh: true,
        );

        if ($session === null) {
            throw AuthenticationException::invalidRefreshCredential();
        }

        $validation = $this->validateSession($session);

        $authenticatable = $this->provider->find(
            (int) $session->authenticatable_id,
            cache: false,
        );

        if ($authenticatable === null) {
            $session->delete();
            $this->session = null;

            throw AuthenticationException::authenticatableNotFound();
        }

        if (!$validation->isRefreshable()) {
            $session->delete();
            $this->session = null;

            throw AuthenticationException::expiredRefreshCredential();
        }

        $now = now();
        $accessToken = $this->generateToken();

        $accessCredential = match ($this->config->driver) {
            'session' => $accessToken,
            'jwt' => $this->createJwt($authenticatable, $accessToken),
        };

        $sessionData = [
            'access_token_hash' => $this->hashToken($accessToken),
            'access_expires_at' => $now->copy()->addSeconds(
                $this->config->accessLifetime,
            ),
            'last_used_at' => $now,
        ];

        if ($this->config->refreshRotation) {
            $refreshToken = $this->generateToken();

            $sessionData['refresh_token_hash'] = $this->hashToken(
                $refreshToken,
            );
        }

        if ($this->config->refreshPolicy === 'rolling') {
            $sessionData['refresh_expires_at'] = $now->copy()->addSeconds(
                $this->config->refreshLifetime,
            );
        }

        $session->forceFill($sessionData)->save();
        $this->session = $session;

        $credentials = new SessionCredentials(
            access: $accessCredential,
            refresh: $refreshToken,
        );

        $this->source->store($credentials);

        return $credentials;
    }

    /**
     * Revoke the authentication session resolved from the current request.
     *
     * Falls back to the refresh credential when the access credential
     * does not resolve to an existing session.
     */
    public function logout(): void
    {
        $session = $this->authenticatedSession();

        if ($session === null) {
            $session = $this->authenticatedSession(
                credential: 'refresh',
                fresh: true,
            );
        }

        $session?->delete();

        $this->source->clear();
        $this->session = null;
    }

    /**
     * Resolve the current authentication session.
     *
     * Cached sessions are reused for access lookups unless a fresh database
     * lookup is explicitly requested. Refresh lookups always resolve the
     * session using the refresh credential.
     *
     * @param string $credential The credential type used for lookup.
     * @param bool $fresh Whether to retrieve the session from the database.
     *
     * @return AuthSession|null The resolved session, or null if not found.
     *
     * @throws AuthenticationException If the credential type is unsupported.
     */
    protected function authenticatedSession(
        string $credential = 'access',
        bool $fresh = false,
    ): ?AuthSession {
        if (!in_array($credential, ['access', 'refresh'], true)) {
            throw AuthenticationException::unsupportedCredentialType($credential);
        }

        if (
            $credential === 'access'
            && !$fresh
            && $this->session !== null
        ) {
            return $this->session;
        }

        $token = $this->source->access();

        if ($credential === 'refresh') {
            $token = $this->source->refresh();
        }

        if ($token === null || $token === '') {
            if ($credential === 'access') {
                $this->session = null;
            }

            return null;
        }

        $column = 'access_token_hash';

        if ($credential === 'refresh') {
            $column = 'refresh_token_hash';
        } elseif ($this->config->driver === 'jwt') {
            $claims = $this->decodeJwt($token);

            if ($claims === null) {
                $this->session = null;

                return null;
            }

            $token = $claims['jti'];
        }

        $session = AuthSession::query()
            ->where('guard', $this->guard)
            ->where($column, $this->hashToken($token))
            ->first();

        $this->session = $session;

        return $session;
    }

    /**
     * Validate the access and refresh credentials of an authentication session.
     *
     * Resolves the current access session when no session is provided.
     * Removes the session when its authenticatable no longer exists or
     * neither credential remains valid.
     *
     * @param AuthSession|null $session The session to validate, or null to resolve it.
     *
     * @return SessionValidation The validity state of both credentials.
     */
    protected function validateSession(
        ?AuthSession $session = null,
    ): SessionValidation {
        $session ??= $this->authenticatedSession();

        if ($session === null) {
            return new SessionValidation(
                accessValid: false,
                refreshValid: false,
            );
        }

        if ($this->provider->find((int) $session->authenticatable_id) === null) {
            $session->delete();
            $this->session = null;

            return new SessionValidation(
                accessValid: false,
                refreshValid: false,
            );
        }

        $accessValid = $session->access_expires_at !== null
            && $session->access_expires_at->isFuture();

        $refreshValid = $session->refresh_token_hash !== null
            && $session->refresh_expires_at !== null
            && $session->refresh_expires_at->isFuture();

        if (!$accessValid && !$refreshValid) {
            $session->delete();
            $this->session = null;
        }

        return new SessionValidation(
            accessValid: $accessValid,
            refreshValid: $refreshValid,
        );
    }

    /**
     * Retrieve the authenticatable entity associated with a session.
     *
     * Returns null when no session is available or when the associated
     * authenticatable entity no longer exists. In the latter case, the
     * stale session is deleted and the cached session is cleared.
     *
     * Updates the session's activity timestamp when the authenticatable
     * entity is successfully resolved.
     *
     * @param AuthSession|null $session The session to resolve.
     *
     * @return Model|null The authenticatable entity, or null if the session
     *                    or its associated entity does not exist.
     */
    protected function resolveAuthenticatable(?AuthSession $session): ?Model
    {
        if ($session === null) {
            return null;
        }

        $authenticatable = $this->provider->find(
            (int) $session->authenticatable_id,
        );

        if ($authenticatable === null) {
            $session->delete();
            $this->session = null;

            return null;
        }

        $this->updateSessionActivity($session);

        return $authenticatable;
    }

    /**
     * Update the session's last activity timestamp when due.
     */
    protected function updateSessionActivity(AuthSession $session): void
    {
        $now = now();
        $lastUsedAt = $session->last_used_at;

        if (
            $lastUsedAt !== null
            && $lastUsedAt->diffInSeconds($now)
            < $this->config->activityInterval
        ) {
            return;
        }

        $session->forceFill([
            'last_used_at' => $now,
        ])->save();
    }

    /**
     * Create a signed JWT access credential.
     *
     * Custom claims may be supplied by the authenticatable entity. Reserved
     * claims generated by this driver take precedence over custom claims.
     *
     * @throws UnexpectedValueException If jwtClaims() does not return an array.
     */
    protected function createJwt(
        Model $authenticatable,
        string $jti,
    ): string {
        $customClaims = [];

        if (method_exists($authenticatable, 'jwtClaims')) {
            $customClaims = $authenticatable->jwtClaims();

            if (!is_array($customClaims)) {
                throw new UnexpectedValueException(
                    'The jwtClaims() method must return an array.',
                );
            }
        }

        $now = time();

        $claims = array_merge($customClaims, [
            'sub' => (string) $authenticatable->getKey(),
            'jti' => $jti,
            'iat' => $now,
            'exp' => $now + $this->config->accessLifetime,
        ]);

        return (new Jwt())->encode($claims);
    }

    /**
     * Decode a JWT and validate its required identifier claim.
     *
     * @return array<string, mixed>|null Claims, or null for an invalid token.
     *
     * @throws \Fbpkg\Guards\Exceptions\ConfigurationException If JWT configuration is invalid.
     */
    protected function decodeJwt(string $access): ?array
    {
        try {
            $claims = (new Jwt())->decode($access);
        } catch (UnexpectedValueException | JsonException) {
            return null;
        }

        if (
            !isset($claims['jti'])
            || !is_string($claims['jti'])
            || $claims['jti'] === ''
        ) {
            return null;
        }

        return $claims;
    }

    /**
     * Generate a cryptographically secure random token.
     */
    protected function generateToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Hash a raw credential before storing or querying it.
     */
    protected function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }
}
