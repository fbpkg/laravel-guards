<?php

namespace Fbpkg\Guards;

use Fbpkg\Guards\Guards\GuardManager;
use Illuminate\Support\ServiceProvider;

/**
 * Bootstrap the Laravel Guards package.
 */
class GuardsServiceProvider extends ServiceProvider
{
    /**
     * Register package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/guards.php',
            'guards',
        );

        $this->app->singleton('guards', function () {
            return new GuardManager();
        });
    }

    /**
     * Bootstrap package services.
     */
    public function boot(): void
    {
        $this->registerPublishing();
    }

    /**
     * Register package publishing resources.
     */
    protected function registerPublishing(): void
    {
        $this->publishes([
            __DIR__ . '/../config/guards.php' => config_path('guards.php'),
        ], 'guards-config');

        if (empty(glob(database_path('migrations/*_create_auth_sessions_table.php')))) {
            $this->publishes([
                __DIR__ . '/../database/migrations/create_auth_sessions_table.php.stub'
                => database_path(
                    'migrations/' . date('Y_m_d_His') . '_create_auth_sessions_table.php',
                ),
            ], 'guards-migrations');
        }
    }
}
