<?php

namespace ZTrippete\JwtVerifier\Tests;

use ZTrippete\JwtVerifier\Exceptions\TokenFormatException;
use ZTrippete\JwtVerifier\Exceptions\TokenValidationException;
use ZTrippete\JwtVerifier\Tests\Support\RsaKey;
use ZTrippete\JwtVerifier\Tests\Support\TestCase;

/**
 * A malformed token must be rejected before any HTTP call to the provider
 */
final class HeaderValidationTest extends TestCase
{
    /**
     * @dataProvider invalidKidProvider
     */
    public function testInvalidKidThrowsTokenFormatExceptionWithoutHttpCall(array $header): void
    {
        $this->assertRejectedWithoutHttpCall($this->rawToken($header), TokenFormatException::class);
    }

    public static function invalidKidProvider(): array
    {
        return [
            'missing kid' => [['alg' => 'RS256', 'typ' => 'JWT']],
            'null kid' => [['alg' => 'RS256', 'kid' => null]],
            'empty kid' => [['alg' => 'RS256', 'kid' => '']],
            'integer kid' => [['alg' => 'RS256', 'kid' => 123]],
            'array kid' => [['alg' => 'RS256', 'kid' => ['a']]],
        ];
    }

    /**
     * @dataProvider invalidAlgProvider
     */
    public function testInvalidAlgThrowsTokenValidationExceptionWithoutHttpCall(array $header): void
    {
        $this->assertRejectedWithoutHttpCall($this->rawToken($header), TokenValidationException::class);
    }

    public static function invalidAlgProvider(): array
    {
        return [
            'missing alg' => [['kid' => 'kid-a']],
            'none' => [['alg' => 'none', 'kid' => 'kid-a']],
            'HS256' => [['alg' => 'HS256', 'kid' => 'kid-a']],
            'RS512' => [['alg' => 'RS512', 'kid' => 'kid-a']],
            'lowercase rs256' => [['alg' => 'rs256', 'kid' => 'kid-a']],
        ];
    }

    /**
     * @dataProvider malformedTokenProvider
     */
    public function testMalformedTokenThrowsTokenFormatExceptionWithoutHttpCall(string $token): void
    {
        $this->assertRejectedWithoutHttpCall($token, TokenFormatException::class);
    }

    public static function malformedTokenProvider(): array
    {
        return [
            'not a jwt' => ['not-a-jwt'],
            'two segments' => ['abc.def'],
            'invalid base64 header' => ['%%%.e30.c2ln'],
            'header not json' => [RsaKey::base64Url('nope') . '.e30.c2ln'],
            'encrypted token header' => [RsaKey::base64Url('{"alg":"RS256","kid":"a","enc":"A256GCM"}') . '.e30.c2ln'],
        ];
    }

    /**
     * @param class-string<\Throwable> $exception
     */
    private function assertRejectedWithoutHttpCall(string $token, string $exception): void
    {
        $verifier = $this->verifier(
            [$this->jwksResponse(RsaKey::get('a')->x5cJwk('kid-a'))],
            $this->cacheManager()
        );

        try {
            $verifier->verifyAndGetClaims($token);
            $this->fail($exception . ' expected');
        } catch (\Throwable $e) {
            $this->assertInstanceOf($exception, $e, $e->getMessage());
        }

        $this->assertCount(0, $this->httpHistory);
        $this->assertSame([], $this->cacheStore);
    }
}
