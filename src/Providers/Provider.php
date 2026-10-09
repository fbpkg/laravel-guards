<?php

namespace Fbpkg\Guards\Providers;

use Fbpkg\Guards\Contracts\Provider as ProviderContract;
use Fbpkg\Guards\Types\Config\Provider as ProviderConfig;
use Illuminate\Database\Eloquent\Model;

/**
 * Resolves authenticatable entities using the configured Eloquent model.
 */
class Provider implements ProviderContract
{
    /**
     * Create a new provider instance.
     *
     * @param ProviderConfig $config Resolved provider configuration.
     */
    public function __construct(
        protected ProviderConfig $config,
    ) {}

    /**
     * Find an authenticatable entity by its unique identifier.
     *
     * @param int $id The unique identifier of the entity.
     *
     * @return Model|null The resolved entity, or null when no matching
     *                    entity exists.
     */
    public function find(int $id): ?Model
    {
        return $this->config->model::find($id);
    }
}
