<?php

namespace Fbpkg\Guards\Sources;

use Fbpkg\Guards\Types\Config\Source as SourceConfig;
use Fbpkg\Guards\Types\SessionCredentials;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;

/**
 * Resolves, stores, and clears authentication credentials.
 *
 * Credentials are resolved from the configured request location.
 * Cookie sources can persist credentials through Laravel's queued
 * cookies and update the current request to reflect credential changes.
 */
class Source
{
    /**
     * The resolved access credential.
     */
    protected ?string $access = null;

    /**
     * The resolved refresh credential.
     */
    protected ?string $refresh = null;

    /**
     * Create a new source instance.
     *
     * @param SourceConfig $config The resolved source configuration.
     * @param Request      $request The current HTTP request.
     */
    public function __construct(
        protected SourceConfig $config,
        protected Request $request,
    ) {
        $this->resolve();
    }

    /**
     * Get the resolved access credential.
     *
     * @return string|null The access credential, or null if unavailable.
     */
    public function access(): ?string
    {
        return $this->access;
    }

    /**
     * Get the resolved refresh credential.
     *
     * @return string|null The refresh credential, or null if unavailable.
     */
    public function refresh(): ?string
    {
        return $this->refresh;
    }

    /**
     * Determine whether this source uses cookies.
     *
     * @return bool True if the source is cookie-based; otherwise false.
     */
    public function isCookieSource(): bool
    {
        return $this->config->type === 'cookie';
    }

    /**
     * Store authentication credentials in the configured source.
     *
     * For cookie sources, queues the credentials for the current response
     * and updates this source instance's cached values.
     *
     * Other source types are not modified.
     *
     * If a refresh cookie is configured but no refresh credential is
     * provided, the existing refresh cookie is queued for removal.
     *
     * @param SessionCredentials $credentials The credentials to store.
     */
    public function store(SessionCredentials $credentials): void
    {
        if (!$this->isCookieSource()) {
            return;
        }

        $this->setCookie(
            $this->config->access,
            $credentials->access,
        );

        $this->access = $credentials->access;

        if ($this->config->refresh === null) {
            return;
        }

        if ($credentials->refresh === null) {
            $this->forgetCookie($this->config->refresh);
            $this->refresh = null;

            return;
        }

        $this->setCookie(
            $this->config->refresh,
            $credentials->refresh,
        );

        $this->refresh = $credentials->refresh;
    }

    /**
     * Clear authentication credentials belonging to this source.
     *
     * For cookie sources, queues the configured cookies for removal
     * and clears this source instance's cached values.
     *
     * Other source types are not modified.
     */
    public function clear(): void
    {
        if (!$this->isCookieSource()) {
            return;
        }

        $this->forgetCookie($this->config->access);

        if ($this->config->refresh !== null) {
            $this->forgetCookie($this->config->refresh);
        }

        $this->access = null;
        $this->refresh = null;
    }

    /**
     * Queue a cookie to be set in the current HTTP response.
     *
     * @param string $name The cookie name.
     * @param string $value The cookie value.
     */
    protected function setCookie(string $name, string $value): void
    {
        Cookie::queue(Cookie::make(
            name: $name,
            value: $value,
        ));
    }

    /**
     * Queue a cookie for removal in the current HTTP response.
     *
     * The browser removes the cookie when it receives the expired cookie
     * in the response. The cookie does not need to exist beforehand.
     *
     * @param string $name The cookie name.
     */
    protected function forgetCookie(string $name): void
    {
        Cookie::queue(Cookie::forget($name));
    }

    /**
     * Resolve the configured credentials from the current request.
     *
     * Both credentials are resolved once and cached on this instance.
     */
    protected function resolve(): void
    {
        $this->access = $this->resolveValue(
            $this->config->access,
        );

        if ($this->config->scheme !== null) {
            $this->access = $this->removeScheme(
                $this->access,
            );
        }

        if ($this->config->refresh !== null) {
            $this->refresh = $this->resolveValue(
                $this->config->refresh,
            );
        }
    }

    /**
     * Resolve a credential from the configured request location.
     *
     * @param string $name The credential name.
     *
     * @return string|null The credential value, or null if unavailable.
     */
    protected function resolveValue(string $name): ?string
    {
        return match ($this->config->type) {
            'cookie' => $this->request->cookie($name),
            'header' => $this->request->header($name),
            'body' => $this->request->input($name),
            'query' => $this->request->query($name),
        };
    }

    /**
     * Remove the configured scheme from a credential value.
     *
     * @param string|null $value The original credential value.
     *
     * @return string|null The credential without its scheme, or null
     *                     if it does not match the configured scheme.
     */
    protected function removeScheme(?string $value): ?string
    {
        if ($value === null || $this->config->scheme === null) {
            return $value;
        }

        $scheme = $this->config->scheme . ' ';

        if (!str_starts_with(
            strtolower($value),
            strtolower($scheme),
        )) {
            return null;
        }

        return substr($value, strlen($scheme));
    }
}
