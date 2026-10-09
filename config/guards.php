<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Default Authentication Settings
    |--------------------------------------------------------------------------
    |
    | Settings inherited by guards unless explicitly overridden.
    |
    | Supported drivers: session, jwt.
    | Supported JWT states: session, none.
    | Refresh policies: fixed, rolling.
    |
    */

    'defaults' => [
        'guard' => env('GUARDS_DEFAULT', 'web'),

        'driver' => 'session',
        'state' => 'session',

        'access_lifetime' => 3600,      // 1 hour
        'refresh_lifetime' => 2592000,  // 30 days

        'activity_interval' => 60,      // 1 minute

        'refresh_policy' => 'rolling',
        'refresh_rotation' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | JSON Web Token (JWT)
    |--------------------------------------------------------------------------
    |
    | Supported algorithms: HS256, ES256.
    | Use HS256 when all token validators are trusted to issue tokens.
    | Use ES256 when other services must verify tokens without signing them.
    |
    */

    'jwt' => [
        'algorithm' => env('GUARDS_JWT_ALGORITHM', 'HS256'),

        'secret' => env('GUARDS_JWT_SECRET'),

        'private_key' => env('GUARDS_JWT_PRIVATE_KEY'),
        'public_key' => env('GUARDS_JWT_PUBLIC_KEY'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Guards
    |--------------------------------------------------------------------------
    |
    | Named authentication contexts. Each guard defines its driver,
    | provider, source, and optional settings that override defaults.
    |
    */

    'guards' => [
        'web' => [
            'provider' => 'users',
            // 'source' => 'web',
            'source' => 'spa',
        ],

        'admin' => [
            'provider' => 'admins',
            'source' => 'admin',
            'refresh_rotation' => false,
        ],

        'spa' => [
            'driver' => 'jwt',
            'provider' => 'users',
            'source' => 'spa',
        ],

        'mobile' => [
            'driver' => 'jwt',
            'provider' => 'users',
            'source' => 'spa',
            'state' => 'none',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Providers
    |--------------------------------------------------------------------------
    |
    | Providers map names to the Eloquent models used to resolve
    | authenticatable entities.
    |
    */

    'providers' => [
        'users' => App\Models\User::class,
        // 'admins' => App\Models\Admin::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Sources
    |--------------------------------------------------------------------------
    |
    | Sources define where authentication credentials are extracted
    | from the current HTTP request.
    |
    | Supported types: cookie, header, body, query.
    |
    */

    'sources' => [
        'web' => [
            'type' => 'cookie',
            'access' => env('GUARDS_COOKIE_NAME', 'guards_auth'),
            'refresh' => env('GUARDS_REFRESH_COOKIE_NAME', 'guards_refresh'),
        ],

        'admin' => [
            'type' => 'cookie',
            'access' => env('GUARDS_ADMIN_COOKIE_NAME', 'guards_admin_auth'),
            'refresh' => env('GUARDS_ADMIN_REFRESH_COOKIE_NAME', 'guards_admin_refresh'),
        ],

        'spa' => [
            'type' => 'header',
            'access' => 'Authorization',
            'refresh' => 'X-Refresh-Token',
            'scheme' => 'bearer',
        ],
    ],

];
