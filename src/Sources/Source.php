<?php

namespace Fbpkg\Guards\Sources;

use Fbpkg\Guards\Types\Config\Source as SourceConfig;
use Illuminate\Http\Request;

/**
 * Resolves authentication credentials from the current request.
 *
 * A source defines how access and refresh credentials are extracted
 * from the configured request location.
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
     * @param SourceConfig $config  Resolved source configuration.
     * @param Request      $request Current HTTP request.
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
     * @return string|null The access credential.
     */
    public function access(): ?string
    {
        return $this->access;
    }

    /**
     * Get the resolved refresh credential.
     *
     * @return string|null The refresh credential.
     */
    public function refresh(): ?string
    {
        return $this->refresh;
    }

    /**
     * Resolve the configured credentials from the current request.
     *
     * Both access and refresh credentials are resolved in a single
     * operation and stored on the source instance.
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
     * Resolve a credential value from the current request.
     *
     * @param string $name Credential name.
     *
     * @return string|null The resolved credential value.
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
     * @param string|null $value The resolved credential value.
     *
     * @return string|null The credential value without its scheme,
     *                     or null when the value does not match the
     *                     configured scheme.
     */
    protected function removeScheme(?string $value): ?string
    {
        if ($value === null || $this->config->scheme === null) {
            return $value;
        }

        $scheme = $this->config->scheme . ' ';

        if (! str_starts_with(
            strtolower($value),
            strtolower($scheme),
        )) {
            return null;
        }

        return substr($value, strlen($scheme));
    }
}
