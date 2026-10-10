<?php

namespace Fbpkg\Guards\Types\Config;

/**
 * Represents the redirect destinations for an authentication guard.
 */
final readonly class Redirects
{
    /**
     * @param string $guest Destination for unauthenticated users.
     * @param string $authenticated Destination for authenticated users.
     */
    public function __construct(
        public string $guest,
        public string $authenticated,
    ) {}
}
