<?php

namespace Fbpkg\Guards\Contracts;

use Fbpkg\Guards\Types\SessionCredentials;
use Illuminate\Database\Eloquent\Model;

/**
 * Defines a runtime authentication driver.
 */
interface Driver
{
    /**
     * Retrieve the authenticated entity for the current request.
     *
     * @return Model|null The authenticated entity, or null when unauthenticated.
     */
    public function authenticatable(): ?Model;

    /**
     * Retrieve the claims from the current JWT access token.
     *
     * Returns null when the configured driver is not JWT or the access
     * token is missing or invalid.
     *
     * @return array<string, mixed>|null The JWT claims, or null when unavailable.
     */
    public function jwtClaims(): ?array;

    /**
     * Authenticate the given entity and issue session credentials.
     *
     * @param Model $authenticatable The entity to authenticate.
     * @param bool $remember Whether to issue a refresh credential.
     *
     * @return SessionCredentials The issued authentication credentials.
     */
    public function login(
        Model $authenticatable,
        bool $remember = false,
    ): SessionCredentials;

    /**
     * Refresh the current authentication credentials.
     *
     * @return SessionCredentials The refreshed authentication credentials.
     */
    public function refresh(): SessionCredentials;

    /**
     * Invalidate the current authentication session.
     *
     * @return void
     */
    public function logout(): void;
}
