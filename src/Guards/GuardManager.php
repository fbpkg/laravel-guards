<?php

namespace Fbpkg\Guards\Guards;

use Fbpkg\Guards\Support\Config;
use Illuminate\Database\Eloquent\Model;
use Fbpkg\Guards\Types\SessionCredentials;

/**
 * Manages authentication guards.
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
     * Resolve a guard instance.
     */
    public function guard(?string $name = null): Guard
    {
        $name ??= Config::defaultGuard();

        return $this->guards[$name] ??= new Guard($name);
    }

    /**
     * Determine whether the default guard is authenticated.
     */
    public function check(): bool
    {
        return $this->guard()->check();
    }

    /**
     * Get the authenticated user from the default guard.
     */
    public function user(): ?Model
    {
        return $this->guard()->user();
    }

    /**
     * Authenticate a user using the default guard.
     */
    public function login(
        Model $authenticatable,
        bool $remember = false,
    ): SessionCredentials {
        return $this->guard()->login($authenticatable, $remember);
    }

    /**
     * Refresh credentials using the default guard.
     */
    public function refresh(): SessionCredentials
    {
        return $this->guard()->refresh();
    }

    /**
     * Log out from the default guard.
     */
    public function logout(): void
    {
        $this->guard()->logout();
    }
}
