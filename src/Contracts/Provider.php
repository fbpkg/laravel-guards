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
     * @param int $id The unique identifier of the entity.
     *
     * @return Model|null The resolved entity, or null when no matching
     *                    entity exists.
     */
    public function find(int $id): ?Model;
}
