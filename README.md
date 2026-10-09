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

The package generally uses `src/Support/Config.php` to resolve configuration values, apply defaults and guard-specific overrides, and validate configuration where applicable.

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

### Providers

The `providers` section maps provider names to Eloquent model classes. Providers resolve the authenticatable entities used by the guards.

For example:

```php
'providers' => [
    'users' => App\Models\User::class,
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
if (Guards::guard('admin')->check()) {
    $admin = Guards::guard('admin')->user();
}
```

### Logging in

Pass an authenticatable model to the login operation:

```php
$credentials = Guards::login($user, remember: true);
```

The operation returns a `SessionCredentials` object containing the credentials issued by the configured driver.

The `remember` argument controls whether refresh credentials are requested. The exact credential properties and their availability depend on the implementation.

Transmit and store credentials according to the configured credential source. Treat refresh credentials as sensitive secrets.

### Refreshing credentials

Use a valid refresh credential to request renewed credentials:

```php
$credentials = Guards::refresh($refreshToken);
```

Refresh behavior depends on the guard configuration, including the refresh policy and whether refresh-token rotation is enabled.

### Logging out

Log out through the guard manager:

```php
Guards::logout();
```

Logout invalidates the current authentication session according to the configured driver.

## Database and Credential Security

The package stores authentication credential hashes rather than raw credentials in the authentication sessions table.

For production deployments:

- Use HTTPS for credential transmission.
- Keep JWT signing secrets and private keys secure.
- Protect refresh credentials against unauthorized access.
- Configure appropriate access and refresh lifetimes.
- Review the authentication state and refresh policy for each guard.
- Ensure that the application's credential transport matches the configured source.

## Error Handling

The package provides exceptions for authentication failures and configuration errors.

Handle authentication failures at your application's HTTP or API boundary and return responses appropriate to your application. Avoid exposing internal exception details or sensitive credential data to clients.

## Development Status

Laravel Guards is under active development. Review the configuration and public API of the installed version before integrating it into a production application.

## License

This package is open-sourced software licensed under the [MIT license](LICENSE).