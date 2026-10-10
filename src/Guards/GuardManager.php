<?php

namespace Fbpkg\Guards\Guards;

use Fbpkg\Guards\Support\Config;
use Fbpkg\Guards\Types\SessionCredentials;
use Illuminate\Database\Eloquent\Model;

/**
 * Manages authentication guards and exposes the default guard's operations.
 */
class GuardManager
{
    /**
     * Resolved guard instances.
     *
     * @var array<string, Guard>
     */
    protected array $guards = [];

    /**
     * Resolve an authentication guard by name.
     *
     * Uses the configured default guard when no name is provided.
     *
     * @param string|null $name The guard name, or null for the default guard.
     *
     * @return Guard The resolved guard instance.
     */
    public function guard(?string $name = null): Guard
    {
        $name ??= Config::defaultGuard();

        return $this->guards[$name] ??= new Guard($name);
    }

    /**
     * Determine whether the default guard is authenticated.
     *
     * @return bool True when an authenticated entity exists.
     */
    public function check(): bool
    {
        return $this->guard()->check();
    }

    /**
     * Retrieve the authenticated entity from the default guard.
     *
     * @return Model|null The authenticated entity, or null when unauthenticated.
     */
    public function user(): ?Model
    {
        return $this->guard()->user();
    }

    /**
     * Retrieve the JWT claims from the default guard's access token.
     *
     * Returns null when the configured driver is not JWT or the access
     * token is missing or invalid.
     *
     * @return array<string, mixed>|null The JWT claims, or null when unavailable.
     */
    public function jwtClaims(): ?array
    {
        return $this->guard()->jwtClaims();
    }

    /**
     * Authenticate an entity using the default guard.
     *
     * @param Model $authenticatable The entity to authenticate.
     * @param bool $remember Whether to issue a refresh credential.
     *
     * @return SessionCredentials The issued authentication credentials.
     */
    public function login(
        Model $authenticatable,
        bool $remember = false,
    ): SessionCredentials {
        return $this->guard()->login($authenticatable, $remember);
    }

    /**
     * Refresh credentials using the default guard.
     *
     * @return SessionCredentials The refreshed authentication credentials.
     *
     * @throws \Fbpkg\Guards\Exceptions\AuthenticationException
     */
    public function refresh(): SessionCredentials
    {
        return $this->guard()->refresh();
    }

    /**
     * Invalidate the authentication session for the default guard.
     *
     * @return void
     */
    public function logout(): void
    {
        $this->guard()->logout();
    }
}
