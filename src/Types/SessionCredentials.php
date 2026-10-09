<?php

namespace Fbpkg\Guards\Types;

/**
 * Represents the credentials issued for an authentication session.
 *
 * An access credential is always present, while a refresh credential is
 * optional and is issued only when refresh authentication is enabled.
 *
 * @property-read string      $access
 * @property-read string|null $refresh
 */
final readonly class SessionCredentials
{
    /**
     * @param string      $access  Access credential.
     * @param string|null $refresh Refresh credential.
     */
    public function __construct(
        public string $access,
        public ?string $refresh,
    ) {}
}
