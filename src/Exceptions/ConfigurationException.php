<?php

namespace Fbpkg\Guards\Exceptions;

use RuntimeException;

class ConfigurationException extends RuntimeException
{
    /**
     * Create an exception for an invalid configuration value.
     *
     * @param string $message Configuration error message.
     */
    public static function invalid(string $message): static
    {
        return new static($message);
    }

    /**
     * Create an exception for a missing configuration value.
     *
     * @param string $key Configuration key.
     */
    public static function missing(string $key): static
    {
        return new static(
            "The configuration key [{$key}] is missing or has a null value."
        );
    }

    /**
     * Create an exception for a missing default configuration value.
     *
     * @param string $key Default configuration key.
     */
    public static function missingDefault(string $key): static
    {
        return new static(
            "The default configuration key [{$key}] is missing or has a null value."
        );
    }

    /**
     * Create an exception for an undefined authentication guard.
     *
     * @param string $guard Guard name.
     */
    public static function guardNotFound(string $guard): static
    {
        return new static(
            "The authentication guard [{$guard}] is not configured."
        );
    }

    /**
     * Create an exception for an undefined authentication provider.
     *
     * @param string $provider Provider name.
     */
    public static function providerNotFound(string $provider): static
    {
        return new static(
            "The authentication provider [{$provider}] is not configured."
        );
    }

    /**
     * Create an exception for an undefined authentication source.
     *
     * @param string $source Source name.
     */
    public static function sourceNotFound(string $source): static
    {
        return new static(
            "The authentication source [{$source}] is not configured."
        );
    }

    /**
     * Create an exception for an invalid authentication provider configuration.
     *
     * @param string $provider Provider name.
     */
    public static function providerInvalid(string $provider): static
    {
        return new static(
            "The authentication provider [{$provider}] has an invalid model configuration."
        );
    }

    /**
     * Create an exception for a provider model that is not an Eloquent model.
     *
     * @param string $provider Provider name.
     */
    public static function providerMustBeModel(string $provider): static
    {
        return new static(
            "The authentication provider [{$provider}] model must be an Eloquent model."
        );
    }
}
