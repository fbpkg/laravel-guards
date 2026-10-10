<?php

namespace Fbpkg\Guards\Contracts;

use Illuminate\Database\Eloquent\Model;

/**
 * Defines an authenticatable provider.
 */
interface Provider
{
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
    public function find(int $id, bool $cache = true): ?Model;
}
