<?php

namespace ZTrippete\JwtVerifier\Tests;

use ZTrippete\JwtVerifier\Exceptions\JwksFormatException;
use ZTrippete\JwtVerifier\JwkConverter;
use ZTrippete\JwtVerifier\Tests\Support\RsaKey;
use ZTrippete\JwtVerifier\Tests\Support\TestCase;

final class JwkConverterTest extends TestCase
{
    public function testModulusExponentProducesTheSamePublicKeyAsOpenSsl(): void
    {
        $key = RsaKey::get('a');

        $this->assertSame(
            $this->normalize($key->publicPem),
            $this->normalize(JwkConverter::toPem($key->modulusExponentJwk('kid')))
        );
    }

    public function testModulusWithHighBitAndLeadingZeroIsEncodedAsPositiveInteger(): void
    {
        $key = RsaKey::get('a');
        // A redundant leading zero byte in "n" must not change the encoded key
        $jwk = $key->modulusExponentJwk('kid', ['n' => RsaKey::base64Url("\x00" . $key->modulus)]);

        $this->assertSame($this->normalize($key->publicPem), $this->normalize(JwkConverter::toPem($jwk)));
    }

    public function testX5cProducesACertificatePem(): void
    {
        $pem = JwkConverter::toPem(RsaKey::get('a')->x5cJwk('kid'));

        $this->assertStringStartsWith("-----BEGIN CERTIFICATE-----\n", $pem);
        $this->assertNotFalse(openssl_pkey_get_public($pem));
    }

    /**
     * @dataProvider invalidJwkProvider
     */
    public function testInvalidJwkThrowsJwksFormatException(array $jwk): void
    {
        $this->expectException(JwksFormatException::class);
        JwkConverter::toPem($jwk);
    }

    public static function invalidJwkProvider(): array
    {
        return [
            'no material' => [['kty' => 'RSA', 'kid' => 'k']],
            'missing e' => [['kty' => 'RSA', 'kid' => 'k', 'n' => 'AQAB']],
            'not RSA' => [['kty' => 'oct', 'kid' => 'k', 'n' => 'AQAB', 'e' => 'AQAB']],
            'invalid base64url' => [['kty' => 'RSA', 'kid' => 'k', 'n' => '***', 'e' => 'AQAB']],
            'empty n' => [['kty' => 'RSA', 'kid' => 'k', 'n' => '', 'e' => 'AQAB']],
            'non string n' => [['kty' => 'RSA', 'kid' => 'k', 'n' => 123, 'e' => 'AQAB']],
            'garbage x5c' => [['kty' => 'RSA', 'kid' => 'k', 'x5c' => ['bm90IGEgY2VydA==']]],
        ];
    }

    private function normalize(string $pem): string
    {
        return preg_replace('/\s+/', '', $pem);
    }
}
