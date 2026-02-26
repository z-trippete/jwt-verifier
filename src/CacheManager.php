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

    protected function get(string $key)
    {
        return ($this->cacheGet)($key);
    }

    protected function set(string $key, array $jwksData)
    {
        return ($this->cacheSet)($jwksData);
    }

    /**
     * Retrieve data from cache or use closure
     *
     * @param string $key
     * @param Closure $valueResolver
     * @return array
     */
    public function remember(string $key, Closure $valueResolver): array
    {
        $data = $this->get($key);

        if ($data !== null) {
            return $data;
        }

        $data = $valueResolver();

        $this->set($key, $data);

        return $data;
    }
}
