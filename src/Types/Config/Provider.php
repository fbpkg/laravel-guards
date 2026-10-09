<?php

namespace Fbpkg\Guards\Types\Config;

/**
 * Represents the resolved configuration of an authentication provider.
 *
 * A provider configuration defines the model used to resolve
 * authenticatable entities.
 *
 * @property-read string    $model
 */
final readonly class Provider
{
    /**
     * @param string    $model  Eloquent model class used to resolve authenticatable entities.
     */
    public function __construct(
        public string $model,
    ) {}
}
