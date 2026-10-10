<?php

namespace Fbpkg\Guards\Types;

/**
 * Represents the validation state of an authentication session.
 */
final readonly class SessionValidation
{
    /**
     * Create a new session validation result.
     *
     * @param bool $accessValid Whether the access credential is valid.
     * @param bool $refreshValid Whether the refresh credential is valid.
     */
    public function __construct(
        public bool $accessValid,
        public bool $refreshValid,
    ) {}

    /**
     * Determine whether the access credential is valid.
     */
    public function isAuthenticated(): bool
    {
        return $this->accessValid;
    }

    /**
     * Determine whether the session can be refreshed.
     */
    public function isRefreshable(): bool
    {
        return $this->refreshValid;
    }
}
