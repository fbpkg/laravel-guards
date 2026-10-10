<?php

namespace Fbpkg\Guards\Types\Config;

/**
 * Represents the resolved configuration of an authentication guard.
 *
 * A guard configuration contains the settings required to initialize
 * the corresponding runtime authentication guard and driver.
 *
 * Provider and source values contain configuration names. Their runtime
 * objects are resolved later by the authentication driver.
 *
 * @property-read string    $driver
 * @property-read string    $state
 * @property-read string    $provider
 * @property-read string    $source
 * @property-read int       $accessLifetime
 * @property-read int       $refreshLifetime
 * @property-read int       $activityInterval
 * @property-read string    $refreshPolicy
 * @property-read bool      $refreshRotation
 * @property-read Redirects $redirects
 */
final readonly class Guard
{
    /**
     * @param string    $driver             Authentication driver name.
     * @param string    $state              JWT state validation mode.
     * @param string    $provider           Authentication provider name.
     * @param string    $source             Authentication source name.
     * @param int       $accessLifetime     Access token lifetime in seconds.
     * @param int       $refreshLifetime    Refresh token lifetime in seconds.
     * @param int       $activityInterval   Minimum interval between activity updates.
     * @param string    $refreshPolicy      Refresh token lifetime policy.
     * @param bool      $refreshRotation    Whether refresh token rotation is enabled.
     * @param Redirects $redirects          Redirect destinations for this guard.
     */
    public function __construct(
        public string $driver,
        public string $state,

        public string $provider,
        public string $source,

        public int $accessLifetime,
        public int $refreshLifetime,
        public int $activityInterval,

        public string $refreshPolicy,
        public bool $refreshRotation,

        public Redirects $redirects,
    ) {}
}
