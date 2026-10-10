# Laravel Guards

A flexible authentication package for Laravel with configurable guards, authentication drivers, providers, and credential sources.

## Features

- Configurable authentication guards with per-guard overrides.
- Pluggable authentication drivers: session and JWT.
- Eloquent-based authenticatable providers.
- Configurable credential sources for cookies, headers, request bodies, and query parameters.
- Access and refresh credentials with configurable lifetimes.
- Fixed and rolling refresh-token expiration policies.
- Optional refresh-token rotation.
- Hashed authentication credentials stored in the database.
- Configurable JWT signing algorithms: HS256 and ES256.
- A facade and guard manager for accessing authentication functionality.
- Authentication and guest-only route middleware.
- Configurable redirect destinations for each guard.
- Blade directives for checking authentication state.

## Requirements

- PHP 8.2 or later
- Laravel 11, 12, or 13

## Installation

Install the package through Composer:

```bash
composer require fbpkg/laravel-guards
```

### Publish configuration

Publish the package configuration file:

```bash
php artisan vendor:publish --tag=guards-config
```

This publishes `config/guards.php`.

### Publish migrations

Publish the authentication sessions migration:

```bash
php artisan vendor:publish --tag=guards-migrations
```

Run the migration:

```bash
php artisan migrate
```

Review the configuration and set the appropriate authentication options before using the package in production.

## Configuration

The package configuration file is `config/guards.php`. It defines default settings, JWT options, authentication guards, providers, and credential sources.

The package uses `src/Support/Config.php` to resolve configuration values, apply defaults and guard-specific overrides, and validate configuration where applicable.

### Default settings

The `defaults` section defines settings inherited by guards unless explicitly overridden.

These settings include:

| Setting | Description |
| --- | --- |
| `guard` | Default guard name |
| `driver` | Default authentication driver |
| `state` | Default authentication state |
| `access_lifetime` | Access credential lifetime in seconds |
| `refresh_lifetime` | Refresh credential lifetime in seconds |
| `activity_interval` | Minimum interval between activity updates |
| `refresh_policy` | Refresh expiration policy: `fixed` or `rolling` |
| `refresh_rotation` | Whether refresh credentials are rotated |
| `redirects.guest` | Redirect destination for unauthenticated users |
| `redirects.authenticated` | Redirect destination for authenticated users |

Supported authentication drivers are `session` and `jwt`. Supported JWT states are `session` and `none`.

### JWT settings

The `jwt` section configures the signing algorithm and key material.

Supported algorithms:

- **HS256** — uses a shared secret for signing and verification.
- **ES256** — uses an elliptic-curve private key for signing and the corresponding public key for verification.

Configure the appropriate key material for the selected algorithm. Keep secrets and private keys out of source control, and use environment variables or a secret-management system for sensitive values.

JWT signing does not encrypt the token payload. Do not store passwords, private information, or other secrets in JWT claims.

### Guards

The `guards` section defines named authentication contexts. Each guard can specify a provider, a credential source, and overrides for applicable default settings.

For example, an application can configure separate guards for its web interface, administration panel, and API clients.

Resolve a guard by its configured name:

```php
use Fbpkg\Guards\Facades\Guards;

$web = Guards::guard('web');

$admin = Guards::guard('admin');
```

Calling `Guards::guard()` without a name resolves the configured default guard.

### Redirect configuration

Redirect destinations can be configured globally and overridden for individual guards.

For example:

```php
'defaults' => [
    'redirects' => [
        'guest' => '/login',
        'authenticated' => '/dashboard',
    ],
],

'guards' => [
    'admin' => [
        'provider' => 'admins',
        'source' => 'admin',
        'redirects' => [
            'guest' => '/admin/login',
            'authenticated' => '/admin',
        ],
    ],
],
```

The `guest` destination is used when an unauthenticated user attempts to access a protected route with redirect behavior enabled.

The `authenticated` destination is used when an authenticated user attempts to access a guest-only route with redirect behavior enabled.

A guard-specific destination overrides the corresponding default. Any destination not overridden inherits the default value.

### Providers

The `providers` section maps provider names to Eloquent model classes. Providers resolve the authenticatable entities used by the guards.

For example:

```php
'providers' => [
    'users' => App\Models\User::class,
    'admins' => App\Models\Admin::class,
],
```

Ensure that each guard references a provider that exists in the configuration and points to the appropriate model.

### Credential sources

The `sources` section defines where authentication credentials are extracted from incoming HTTP requests.

Supported source types are:

- `cookie`
- `header`
- `body`
- `query`

Each source can define how access and refresh credentials are obtained.

For example, a header source can use the `Authorization` header for access credentials and `X-Refresh-Token` for refresh credentials. A cookie source can use separate cookie names for access and refresh credentials.

Configure sources according to the clients and authentication flows supported by your application.

## Usage

Import the `Guards` facade to access the configured guard manager:

```php
use Fbpkg\Guards\Facades\Guards;
```

### Accessing a guard

Resolve the default guard:

```php
$guard = Guards::guard();
```

Resolve a specific guard:

```php
$guard = Guards::guard('admin');
```

### Checking authentication

Check whether the current request is authenticated:

```php
if (Guards::check()) {
    $user = Guards::user();
}
```

You can also check a specific guard:

```php
$adminGuard = Guards::guard('admin');

if ($adminGuard->check()) {
    $admin = $adminGuard->user();
}
```

### Logging in

Pass an authenticatable model to the login operation:

```php
$credentials = Guards::login($user, remember: true);
```

The operation returns a `SessionCredentials` object containing the credentials issued by the configured driver.

The `remember` argument controls whether refresh credentials are requested. Treat issued credentials as sensitive secrets.

### Refreshing credentials

Refresh the current authentication credentials through the guard manager:

```php
$credentials = Guards::refresh();
```

Refresh behavior depends on the guard configuration, including the refresh policy and whether refresh-token rotation is enabled.

### Logging out

Log out through the guard manager:

```php
Guards::logout();
```

Logout invalidates the current authentication session according to the configured driver.

## Route Middleware

Laravel Guards provides two middleware aliases:

- `guards.auth` — requires an authenticated entity.
- `guards.guest` — restricts access to unauthenticated visitors.

Both middleware accept a guard name and an optional behavior argument.

The supported behaviors are:

| Behavior | `guards.auth` | `guards.guest` |
| --- | --- | --- |
| `redirect` | Redirects unauthenticated users to the guard's guest destination | Redirects authenticated users to the guard's authenticated destination |
| `abort` | Returns HTTP `401 Unauthorized` | Returns HTTP `403 Forbidden` |

If the behavior is omitted, `redirect` is used.

### Protecting routes

Protect a route using the default `web` guard:

```php
use Illuminate\Support\Facades\Route;

Route::middleware('guards.auth')->group(function () {
    Route::get('/dashboard', function () {
        return view('dashboard');
    });
});
```

Specify a guard explicitly:

```php
Route::middleware('guards.auth:admin')->group(function () {
    Route::get('/admin/dashboard', function () {
        return view('admin.dashboard');
    });
});
```

### Using abort behavior

For routes that should return an HTTP error instead of redirecting:

```php
Route::middleware('guards.auth:api,abort')->group(function () {
    Route::get('/api/profile', function () {
        return response()->json([
            'user' => Guards::guard('api')->user(),
        ]);
    });
});
```

Unauthenticated requests receive a `401 Unauthorized` response.

### Restricting guest-only routes

Use `guards.guest` for routes such as login and registration pages:

```php
Route::middleware('guards.guest')->group(function () {
    Route::get('/login', function () {
        return view('auth.login');
    });

    Route::get('/register', function () {
        return view('auth.register');
    });
});
```

Authenticated users are redirected to the configured authenticated destination.

You can specify a guard and use abort behavior:

```php
Route::middleware('guards.guest:admin,abort')->group(function () {
    Route::get('/admin/login', function () {
        return view('admin.auth.login');
    });
});
```

Authenticated users receive a `403 Forbidden` response.

**Note:** These middleware do not automatically store the originally requested URL in the session when redirecting. If your application needs to return users to their intended destination after login, implement that flow separately.

## Blade Directives

Laravel Guards provides two Blade conditional directives:

- `@guardsAuth` — renders its contents when the selected guard is authenticated.
- `@guardsGuest` — renders its contents when the selected guard is not authenticated.

Both directives accept an optional guard name. The default guard is `web`.

### `@guardsAuth`

Display content only to authenticated users:

```blade
@guardsAuth
    <a href="/dashboard">Dashboard</a>
@endguardsAuth
```

Specify a guard:

```blade
@guardsAuth('admin')
    <a href="/admin">Admin Panel</a>
@endguardsAuth
```

### `@guardsGuest`

Display content only to unauthenticated visitors:

```blade
@guardsGuest
    <a href="/login">Login</a>
    <a href="/register">Register</a>
@endguardsGuest
```

Specify a guard:

```blade
@guardsGuest('admin')
    <a href="/admin/login">Admin Login</a>
@endguardsGuest
```

These directives control which Blade content is rendered. They do not replace route middleware or authorize access to protected endpoints. Always protect sensitive routes on the server side.

## Database and Credential Security

The package stores authentication credential hashes rather than raw credentials in the authentication sessions table.

For production deployments:

- Use HTTPS for credential transmission.
- Keep JWT signing secrets and private keys secure.
- Protect refresh credentials against unauthorized access.
- Configure appropriate access and refresh lifetimes.
- Review the authentication state and refresh policy for each guard.
- Ensure that the application's credential transport matches the configured source.
- Use route middleware to protect server-side resources rather than relying on Blade visibility alone.

## Error Handling

The package provides exceptions for authentication failures and configuration errors.

Handle authentication failures at your application's HTTP or API boundary and return responses appropriate to your application. Avoid exposing internal exception details or sensitive credential data to clients.

## Development Status

Laravel Guards is under active development. Review the configuration and public API of the installed version before integrating it into a production application.

## License

This package is open-sourced software licensed under the [MIT license](LICENSE).