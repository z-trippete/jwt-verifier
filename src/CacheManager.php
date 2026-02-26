<?php

namespace ZTrippete\JwtVerifier;

use Closure;

/**
 * @param Closure $cacheGet
 * @param Closure $cacheSet
 */
class CacheManager
{
    public function __construct(
        readonly Closure $cacheGet,
        readonly Closure $cacheSet
    ) {}

    public function get()
    {
        return ($this->cacheGet)();
    }

    public function set(array $jwksData)
    {
        return ($this->cacheSet)($jwksData);
    }
}
