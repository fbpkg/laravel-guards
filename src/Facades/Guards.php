<?php

namespace Fbpkg\Guards\Facades;

use Fbpkg\Guards\Guards\GuardManager;
use Illuminate\Support\Facades\Facade;

/**
 * @method static bool check()
 * @method static \Illuminate\Database\Eloquent\Model|null user()
 * @method static \Fbpkg\Guards\Types\SessionCredentials login(\Illuminate\Database\Eloquent\Model $authenticatable, bool $remember = false)
 * @method static \Fbpkg\Guards\Types\SessionCredentials refresh()
 * @method static void logout()
 * @method static \Fbpkg\Guards\Guards\Guard guard(?string $name = null)
 *
 * @see GuardManager
 */
class Guards extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'guards';
    }
}
