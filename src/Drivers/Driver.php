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
    public function __construct(
        protected string $guard,
        protected GuardConfig $config,
        protected Provider $provider,
        protected Source $source,
    ) {}

    /**
     * Retrieve the authenticated entity for the current request.
     *
     * @return Model|null The authenticated entity, or null if unauthenticated.
     */
    public function authenticatable(): ?Model
    {
        $session = $this->authenticatedSession();

        $authenticatable = $this->validateSession($session);

        if ($authenticatable === null) {
            return null;
        }

        $this->updateSessionActivity($session);

        return $authenticatable;
    }

    /**
     * Create an authentication session for the given entity.
     *
     * @param Model $authenticatable Entity to authenticate.
     * @param bool  $remember Whether to issue a refresh credential.
     *
     * @return SessionCredentials Issued access and refresh credentials.
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

        AuthSession::query()->create($session);

        return new SessionCredentials(
            access: $accessCredential,
            refresh: $refreshToken,
        );
    }

    /**
     * Refresh credentials using the current refresh credential.
     *
     * Refresh rotation replaces the refresh credential when enabled.
     * A rolling refresh policy also renews its expiry.
     *
     * @return SessionCredentials The renewed credentials.
     *
     * @throws AuthenticationException If the refresh credential is missing,
     *                                 invalid, or expired, or its entity
     *                                 cannot be found.
     */
    public function refresh(): SessionCredentials
    {
        $refreshToken = $this->source->refresh();

        if ($refreshToken === null || $refreshToken === '') {
            throw AuthenticationException::missingRefreshCredential();
        }

        $session = AuthSession::query()
            ->where('guard', $this->guard)
            ->where(
                'refresh_token_hash',
                $this->hashToken($refreshToken),
            )
            ->first();

        $authenticatable = $this->validateSession(
            $session,
            refreshing: true,
        );

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

        return new SessionCredentials(
            access: $accessCredential,
            refresh: $refreshToken,
        );
    }

    /**
     * Revoke the authentication session resolved from the current request.
     *
     * The operation has no effect if the access credential does not resolve
     * to an existing session.
     */
    public function logout(): void
    {
        $this->authenticatedSession()?->delete();
    }

    /**
     * Resolve the current session using the configured access mechanism.
     *
     * @return AuthSession|null The resolved session, or null if not found.
     */
    protected function authenticatedSession(): ?AuthSession
    {
        $access = $this->source->access();

        if ($access === null || $access === '') {
            return null;
        }

        if ($this->config->driver === 'jwt') {
            $claims = $this->decodeJwt($access);

            if ($claims === null) {
                return null;
            }

            $access = $claims['jti'];
        }

        return AuthSession::query()
            ->where('guard', $this->guard)
            ->where('access_token_hash', $this->hashToken($access))
            ->first();
    }

    /**
     * Validate an authentication session and resolve its entity.
     *
     * @param AuthSession|null $session Authentication session.
     * @param bool $refreshing Whether the session is being validated for refresh.
     *
     * @return Model|null The authenticated entity, or null if access can be refreshed.
     *
     * @throws AuthenticationException If the session or required credential is invalid.
     */
    protected function validateSession(
        ?AuthSession $session,
        bool $refreshing = false,
    ): ?Model {
        if ($session === null) {
            if ($refreshing) {
                throw AuthenticationException::invalidRefreshCredential();
            }

            return null;
        }

        $authenticatable = $this->provider->find(
            (int) $session->authenticatable_id,
        );

        if ($authenticatable === null) {
            $session->delete();

            throw AuthenticationException::authenticatableNotFound();
        }

        if ($refreshing) {
            if (
                $session->refresh_token_hash === null
                || $session->refresh_expires_at === null
                || $session->refresh_expires_at->isPast()
            ) {
                $session->delete();

                throw AuthenticationException::expiredRefreshCredential();
            }

            return $authenticatable;
        }

        if (
            $session->access_expires_at !== null
            && $session->access_expires_at->isFuture()
        ) {
            return $authenticatable;
        }

        if (
            $session->refresh_token_hash !== null
            && $session->refresh_expires_at !== null
            && $session->refresh_expires_at->isFuture()
        ) {
            return null;
        }

        $session->delete();

        throw AuthenticationException::expiredAccessCredential();
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
     * @throws \Fbpkg\Guards\Exceptions\ConfigurationException If JWT
     *         configuration is invalid.
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
