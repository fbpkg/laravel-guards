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
     * Authenticate the given entity.
     *
     * @param Model $authenticatable Authenticatable entity.
     * @param bool  $remember        Whether to issue a refresh credential.
     *
     * @return SessionCredentials Authentication session credentials.
     */
    public function login(
        Model $authenticatable,
        bool $remember = false,
    ): SessionCredentials;

    /**
     * Refresh the current authentication credentials.
     *
     * @return SessionCredentials Refreshed authentication session credentials.
     */
    public function refresh(): SessionCredentials;

    /**
     * Log out the current authentication session.
     *
     * @return void
     */
    public function logout(): void;
}
