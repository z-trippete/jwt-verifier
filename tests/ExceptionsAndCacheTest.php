<?php

namespace ZTrippete\JwtVerifier\Tests;

use Exception;
use ZTrippete\JwtVerifier\Exceptions\JwksFormatException;
use ZTrippete\JwtVerifier\Exceptions\JwtVerifierException;
use ZTrippete\JwtVerifier\Exceptions\OAuthProviderException;
use ZTrippete\JwtVerifier\Exceptions\TokenExpireException;
use ZTrippete\JwtVerifier\Exceptions\TokenFormatException;
use ZTrippete\JwtVerifier\Exceptions\TokenValidationException;
use ZTrippete\JwtVerifier\Tests\Support\RsaKey;
use ZTrippete\JwtVerifier\Tests\Support\TestCase;

final class ExceptionsAndCacheTest extends TestCase
{
    /**
     * @dataProvider exceptionProvider
     * @param class-string<Exception> $class
     */
    public function testExceptionsShareACommonBaseAndKeepTheirParent(string $class): void
    {
        $exception = new $class('message');

        $this->assertInstanceOf(JwtVerifierException::class, $exception);
        $this->assertInstanceOf(Exception::class, $exception);
        $this->assertSame('message', $exception->getMessage());
    }

    public static function exceptionProvider(): array
    {
        return [
            [JwksFormatException::class],
            [OAuthProviderException::class],
            [TokenExpireException::class],
            [TokenFormatException::class],
            [TokenValidationException::class],
        ];
    }

    public function testEveryFailureCanBeCaughtWithTheBaseClass(): void
    {
        try {
            $this->verifier()->verifyAndGetClaims('garbage');
            $this->fail('Exception expected');
        } catch (JwtVerifierException $e) {
            $this->assertInstanceOf(TokenFormatException::class, $e);
        }
    }

    public function testCacheManagerRememberUsesCachedValue(): void
    {
        $this->cacheStore['k'] = ['cached'];

        $this->assertSame(['cached'], $this->cacheManager()->remember('k', fn() => $this->fail('Resolver must not run')));
    }

    public function testCacheManagerRememberStoresResolvedValueOnMiss(): void
    {
        $this->assertSame(['fresh'], $this->cacheManager()->remember('k', fn() => ['fresh']));
        $this->assertSame(['fresh'], $this->cacheStore['k']);
    }

    public function testCacheManagerRefreshOverwritesCachedValue(): void
    {
        $this->cacheStore['k'] = ['stale'];

        $this->assertSame(['fresh'], $this->cacheManager()->refresh('k', fn() => ['fresh']));
        $this->assertSame(['fresh'], $this->cacheStore['k']);
    }

    public function testRsaKeyFixtureIsUsable(): void
    {
        $this->assertNotFalse(openssl_pkey_get_private(RsaKey::get('a')->privatePem));
    }
}
