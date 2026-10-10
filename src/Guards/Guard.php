<?php

namespace Fbpkg\Guards\Guards;

use Fbpkg\Guards\Contracts\Driver as DriverContract;
use Fbpkg\Guards\Drivers\Driver;
use Fbpkg\Guards\Providers\Provider;
use Fbpkg\Guards\Sources\Source;
use Fbpkg\Guards\Support\Config;
use Fbpkg\Guards\Types\Config\Guard as GuardConfig;
use Fbpkg\Guards\Types\SessionCredentials;
use Illuminate\Database\Eloquent\Model;

/**
 * Represents an authentication guard.
 *
 * Provides a public interface for authentication operations and delegates
 * their implementation to the configured authentication driver.
 */
class Guard
{
    /**
     * The resolved configuration for this guard.
     */
    protected GuardConfig $config;

    /**
     * The authentication driver used by this guard.
     */
    protected DriverContract $driver;

    /**
     * Create a new authentication guard.
     *
     * Resolves the guard configuration and initializes its provider,
     * credential source, and authentication driver.
     *
     * @param string $name The name of the guard.
     */
    public function __construct(
        protected string $name,
    ) {
        $this->config = Config::guard($this->name);

        $provider = Config::provider($this->config->provider);
        $source = Config::source($this->config->source);

        $this->driver = new Driver(
            guard: $this->name,
            config: $this->config,
            provider: new Provider($provider),
            source: new Source($source, request()),
        );
    }

    /**
     * Determine whether the current request is authenticated.
     *
     * @return bool True when an authenticated entity exists.
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Retrieve the authenticated entity for the current request.
     *
     * @return Model|null The authenticated entity, or null when unauthenticated.
     */
    public function user(): ?Model
    {
        return $this->driver->authenticatable();
    }

    /**
     * Retrieve the claims from the current JWT access token.
     *
     * Returns null when the configured driver is not JWT or the access
     * token is missing or invalid.
     *
     * @return array<string, mixed>|null The JWT claims, or null when unavailable.
     */
    public function jwtClaims(): ?array
    {
        return $this->driver->jwtClaims();
    }

    /**
     * Authenticate an entity and issue session credentials.
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
        return $this->driver->login($authenticatable, $remember);
    }

    /**
     * Refresh the current authentication credentials.
     *
     * @return SessionCredentials The refreshed authentication credentials.
     *
     * @throws \Fbpkg\Guards\Exceptions\AuthenticationException
     */
    public function refresh(): SessionCredentials
    {
        return $this->driver->refresh();
    }

    /**
     * Invalidate the current authentication session.
     *
     * @return void
     */
    public function logout(): void
    {
        $this->driver->logout();
    }

    /**
     * Get the redirect destination for unauthenticated users.
     *
     * @return string The guest redirect path.
     */
    public function guestRedirect(): string
    {
        return $this->config->redirects->guest;
    }

    /**
     * Get the redirect destination for authenticated users.
     *
     * @return string The authenticated redirect path.
     */
    public function authenticatedRedirect(): string
    {
        return $this->config->redirects->authenticated;
    }
}
