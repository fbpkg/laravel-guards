<?php

namespace Fbpkg\Guards\Types\Config;

/**
 * Represents the resolved configuration of an authentication source.
 *
 * A source configuration defines where authentication credentials are
 * extracted from the current HTTP request.
 *
 * @property-read string        $type
 * @property-read string        $access
 * @property-read string|null   $refresh
 * @property-read string|null   $scheme
 */
final readonly class Source
{
    /**
     * @param string        $type       Request location type.
     * @param string        $access     Access credential name.
     * @param string|null   $refresh    Refresh credential name.
     * @param string|null   $scheme     Access credential scheme.
     */
    public function __construct(
        public string $type,
        public string $access,
        public ?string $refresh,
        public ?string $scheme,
    ) {}
}
