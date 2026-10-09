<?php

namespace Fbpkg\Guards\Exceptions;

use RuntimeException;

/**
 * Represents an authentication failure.
 */
class AuthenticationException extends RuntimeException
{
    /**
     * Create an exception for a missing refresh credential.
     *
     * @return static Authentication exception.
     */
    public static function missingRefreshCredential(): static
    {
        return new static(
            'A refresh credential is required.',
        );
    }

    /**
     * Create an exception for an invalid refresh credential.
     *
     * @return static Authentication exception.
     */
    public static function invalidRefreshCredential(): static
    {
        return new static(
            'The refresh credential is invalid.',
        );
    }

    /**
     * Create an exception for an expired access credential.
     *
     * @return static Authentication exception.
     */
    public static function expiredAccessCredential(): static
    {
        return new static(
            'The access credential has expired.',
        );
    }

    /**
     * Create an exception for an expired refresh credential.
     *
     * @return static Authentication exception.
     */
    public static function expiredRefreshCredential(): static
    {
        return new static(
            'The refresh credential has expired.',
        );
    }

    /**
     * Create an exception for a missing authenticatable entity.
     *
     * @return static Authentication exception.
     */
    public static function authenticatableNotFound(): static
    {
        return new static('The authenticatable entity for the authentication session was not found.');
    }
}
