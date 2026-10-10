<?php

namespace Fbpkg\Guards\Support;

use Fbpkg\Guards\Exceptions\ConfigurationException;
use Fbpkg\Guards\Types\Config\ApiKey;
use Fbpkg\Guards\Types\Config\Guard;
use Fbpkg\Guards\Types\Config\Provider;
use Fbpkg\Guards\Types\Config\Redirects;
use Fbpkg\Guards\Types\Config\Source;
use Illuminate\Database\Eloquent\Model;

/**
 * Provides access to the package authentication configuration.
 *
 * This class is responsible for retrieving and resolving configuration
 * values into their corresponding typed configuration objects.
 */
class Config
{
    /**
     * The configuration key prefix used by the package.
     */
    protected const PREFIX = 'guards';

    /**
     * Retrieve the given configuration value.
     *
     * Throws an exception when the requested configuration key does not
     * exist or has a null value.
     *
     * @param string $key Configuration key relative to the package prefix.
     *
     * @return mixed The configured value.
     *
     * @throws ConfigurationException
     */
    protected static function get(string $key): mixed
    {
        $value = config(self::PREFIX . '.' . $key);

        if ($value === null) {
            throw ConfigurationException::missing($key);
        }

        return $value;
    }

    /**
     * Retrieve the given default authentication setting.
     *
     * Throws an exception when the requested default setting does not
     * exist or has a null value.
     *
     * @param string $key Default setting key.
     *
     * @return mixed The configured default value.
     *
     * @throws ConfigurationException
     */
    protected static function getDefault(string $key): mixed
    {
        $defaults = self::get('defaults');

        if (!array_key_exists($key, $defaults) || $defaults[$key] === null) {
            throw ConfigurationException::missingDefault($key);
        }

        return $defaults[$key];
    }

    /**
     * Get the default authentication guard name.
     *
     * @return string The default guard name.
     *
     * @throws ConfigurationException
     */
    public static function defaultGuard(): string
    {
        return self::getDefault('guard');
    }

    /**
     * Get the default authentication driver.
     *
     * @return string The default driver name.
     *
     * @throws ConfigurationException
     */
    public static function defaultDriver(): string
    {
        return self::getDefault('driver');
    }

    /**
     * Get the default JWT state validation mode.
     *
     * @return string The default JWT state.
     *
     * @throws ConfigurationException
     */
    public static function defaultState(): string
    {
        return self::getDefault('state');
    }

    /**
     * Get the default access token lifetime in seconds.
     *
     * @return int The default access token lifetime.
     *
     * @throws ConfigurationException
     */
    public static function defaultAccessLifetime(): int
    {
        return self::getDefault('access_lifetime');
    }

    /**
     * Get the default refresh token lifetime in seconds.
     *
     * @return int The default refresh token lifetime.
     *
     * @throws ConfigurationException
     */
    public static function defaultRefreshLifetime(): int
    {
        return self::getDefault('refresh_lifetime');
    }

    /**
     * Get the default activity update interval in seconds.
     *
     * @return int The default activity interval.
     *
     * @throws ConfigurationException
     */
    public static function defaultActivityInterval(): int
    {
        return self::getDefault('activity_interval');
    }

    /**
     * Get the default refresh token policy.
     *
     * @return string The default refresh token policy.
     *
     * @throws ConfigurationException
     */
    public static function defaultRefreshPolicy(): string
    {
        return self::getDefault('refresh_policy');
    }

    /**
     * Determine whether refresh token rotation is enabled by default.
     *
     * @return bool True when refresh token rotation is enabled.
     *
     * @throws ConfigurationException
     */
    public static function defaultRefreshRotation(): bool
    {
        return self::getDefault('refresh_rotation');
    }

    /**
     * Get the default redirect destinations.
     *
     * @return Redirects The default redirect destinations.
     *
     * @throws ConfigurationException If the default redirects are invalid.
     */
    public static function defaultRedirects(): Redirects
    {
        $redirects = self::getDefault('redirects');

        if (
            !is_array($redirects)
            || !isset($redirects['guest'], $redirects['authenticated'])
            || !is_string($redirects['guest'])
            || !is_string($redirects['authenticated'])
        ) {
            throw ConfigurationException::invalid(
                'The default redirect configuration must contain string values for [guest] and [authenticated].',
            );
        }

        return new Redirects(
            guest: $redirects['guest'],
            authenticated: $redirects['authenticated'],
        );
    }

    /**
     * Resolve the configuration of the given authentication provider.
     *
     * @param string $provider Provider name.
     *
     * @return Provider The resolved provider configuration.
     *
     * @throws ConfigurationException
     */
    public static function provider(string $provider): Provider
    {
        $providers = self::get('providers');

        if (!array_key_exists($provider, $providers)) {
            throw ConfigurationException::providerNotFound($provider);
        }

        $model = $providers[$provider];

        if (!is_string($model) || $model === '') {
            throw ConfigurationException::providerInvalid($provider);
        }

        if (!is_a($model, Model::class, true)) {
            throw ConfigurationException::providerMustBeModel($provider);
        }

        return new Provider(
            model: $model,
        );
    }

    /**
     * Resolve the configuration of the given authentication source.
     *
     * @param string $source Source name.
     *
     * @return Source The resolved source configuration.
     *
     * @throws ConfigurationException
     */
    public static function source(string $source): Source
    {
        $sources = self::get('sources');

        if (!array_key_exists($source, $sources)) {
            throw ConfigurationException::sourceNotFound($source);
        }

        $config = $sources[$source];

        return new Source(
            type: $config['type'],
            access: $config['access'],
            refresh: $config['refresh'] ?? null,
            scheme: $config['scheme'] ?? null,
        );
    }

    /**
     * Resolve the complete configuration of the given authentication guard.
     *
     * Guard-specific settings override the corresponding package defaults.
     * Provider and source values contain configuration names and are resolved
     * into their runtime objects when the authentication driver is initialized.
     *
     * @param string $guard Guard name.
     *
     * @return Guard The fully resolved guard configuration.
     *
     * @throws ConfigurationException If the guard or its configuration is invalid.
     */
    public static function guard(string $guard): Guard
    {
        $guards = self::get('guards');

        if (!array_key_exists($guard, $guards)) {
            throw ConfigurationException::guardNotFound($guard);
        }

        $config = $guards[$guard];

        $defaultRedirects = self::defaultRedirects();
        $guardRedirects = $config['redirects'] ?? [];

        if (!is_array($guardRedirects)) {
            throw ConfigurationException::invalid(
                "The redirect configuration for guard [{$guard}] must be an array.",
            );
        }

        $redirects = new Redirects(
            guest: $guardRedirects['guest'] ?? $defaultRedirects->guest,
            authenticated: $guardRedirects['authenticated'] ?? $defaultRedirects->authenticated,
        );

        return new Guard(
            driver: $config['driver'] ?? self::defaultDriver(),
            state: $config['state'] ?? self::defaultState(),

            provider: $config['provider'],
            source: $config['source'],

            accessLifetime: $config['access_lifetime']
                ?? self::defaultAccessLifetime(),

            refreshLifetime: $config['refresh_lifetime']
                ?? self::defaultRefreshLifetime(),

            activityInterval: $config['activity_interval']
                ?? self::defaultActivityInterval(),

            refreshPolicy: $config['refresh_policy']
                ?? self::defaultRefreshPolicy(),

            refreshRotation: $config['refresh_rotation']
                ?? self::defaultRefreshRotation(),

            redirects: $redirects,
        );
    }

    /**
     * Resolve the API key authentication configuration.
     *
     * @return ApiKey The resolved API key configuration.
     *
     * @throws ConfigurationException
     */
    public static function apiKey(): ApiKey
    {
        $config = self::get('api_key');

        return new ApiKey(
            provider: self::provider($config['provider']),
            source: self::source($config['source']),
        );
    }

    /**
     * Get the configured JWT signing algorithm.
     *
     * @return string The JWT algorithm.
     *
     * @throws ConfigurationException
     */
    public static function jwtAlgorithm(): string
    {
        $algorithm = self::get('jwt')['algorithm'] ?? null;

        if (!in_array($algorithm, ['HS256', 'ES256'], true)) {
            throw ConfigurationException::invalid(
                'The JWT algorithm must be either HS256 or ES256.',
            );
        }

        return $algorithm;
    }

    /**
     * Get the JWT shared secret.
     *
     * @return string The JWT shared secret.
     *
     * @throws ConfigurationException
     */
    public static function jwtSecret(): string
    {
        $secret = self::get('jwt')['secret'] ?? null;

        if (!is_string($secret) || strlen($secret) < 32) {
            throw ConfigurationException::invalid(
                'The JWT secret must be at least 32 bytes long when using HS256.',
            );
        }

        return $secret;
    }

    /**
     * Get the JWT private key.
     *
     * @return string The JWT private key or file path.
     *
     * @throws ConfigurationException
     */
    public static function jwtPrivateKey(): string
    {
        $key = self::get('jwt')['private_key'] ?? null;

        if (!is_string($key) || $key === '') {
            throw ConfigurationException::invalid(
                'The JWT private key must be configured when using ES256.',
            );
        }

        return $key;
    }

    /**
     * Get the JWT public key.
     *
     * @return string The JWT public key or file path.
     *
     * @throws ConfigurationException
     */
    public static function jwtPublicKey(): string
    {
        $key = self::get('jwt')['public_key'] ?? null;

        if (!is_string($key) || $key === '') {
            throw ConfigurationException::invalid(
                'The JWT public key must be configured when using ES256.',
            );
        }

        return $key;
    }
}
