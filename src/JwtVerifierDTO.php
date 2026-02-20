<?php

namespace ZTrippete\JwtVerifier;

use Closure;

/**
 * @param string|null $tokenString
 * @param array|null $config
 * @param Closure|null $cacheSet = null
 * @param Closure|null $cacheGet = null
 * @param string|null $cacheKey = null
 */
class JwtVerifierDTO
{
    public function __construct(
        readonly ?string $tokenString,
        readonly ?array $config,
        readonly ?Closure $cacheSet = null,
        readonly ?Closure $cacheGet = null,
        readonly ?string $cacheKey = null
    ) {}
}
