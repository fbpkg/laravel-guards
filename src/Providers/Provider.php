<?php

namespace Fbpkg\Guards\Providers;

use Fbpkg\Guards\Contracts\Provider as ProviderContract;
use Fbpkg\Guards\Types\Config\Provider as ProviderConfig;
use Illuminate\Database\Eloquent\Model;

/**
 * Resolves and caches authenticatable entities using the configured
 * Eloquent model.
 */
class Provider implements ProviderContract
{
    /**
     * The resolved authenticatable entities indexed by their IDs.
     *
     * @var array<int, Model|null>
     */
    protected array $cache = [];

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
     * Results are cached by default, including missing entities.
     * Set $cache to false to retrieve a fresh result from the database
     * and replace the cached result.
     *
     * @param int  $id    The unique identifier of the entity.
     * @param bool $cache Whether to use the cached result.
     *
     * @return Model|null The resolved entity, or null when no matching
     *                    entity exists.
     */
    public function find(int $id, bool $cache = true): ?Model
    {
        if (!$cache || !array_key_exists($id, $this->cache)) {
            $this->cache[$id] = $this->retrieve($id);
        }

        return $this->cache[$id];
    }

    /**
     * Retrieve an authenticatable entity using the configured model.
     *
     * @param int $id The unique identifier of the entity.
     *
     * @return Model|null The resolved entity, or null when no matching
     *                    entity exists.
     */
    protected function retrieve(int $id): ?Model
    {
        return $this->config->model::find($id);
    }
}
