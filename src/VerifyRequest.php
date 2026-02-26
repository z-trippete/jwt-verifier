<?php

namespace ZTrippete\JwtVerifier;

/**
 * @param string|null $tokenString
 * @param string $jwksUrl
 * @param string $issuer
 * @param string $audience
 * @param CacheManager|null $cacheManager = null
 */
class VerifyRequest
{
    public function __construct(
        readonly ?string $tokenString,
        readonly string $jwksUrl,
        readonly string $issuer,
        readonly string $audience,
        readonly ?CacheManager $cacheManager = null
    ) {}
}
