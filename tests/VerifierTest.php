<?php

namespace ZTrippete\JwtVerifier\Tests;

use Lcobucci\JWT\Token\Builder;
use ZTrippete\JwtVerifier\Exceptions\JwksFormatException;
use ZTrippete\JwtVerifier\Exceptions\TokenValidationException;
use ZTrippete\JwtVerifier\Tests\Support\RsaKey;
use ZTrippete\JwtVerifier\Tests\Support\TestCase;
use ZTrippete\JwtVerifier\Verifier;

final class VerifierTest extends TestCase
{
    public function testValidTokenReturnsClaims(): void
    {
        $key = RsaKey::get('a');
        $verifier = $this->verifier([$this->jwksResponse($key->x5cJwk('kid-a'))]);

        $claims = $verifier->verifyAndGetClaims($this->token($key, 'kid-a'));

        $this->assertSame(self::ISSUER, $claims['iss']);
        $this->assertSame([self::AUDIENCE], $claims['aud']);
        $this->assertSame('user-1', $claims['sub']);
        $this->assertCount(1, $this->httpHistory);
        $this->assertSame('GET', $this->httpHistory[0]['request']->getMethod());
        $this->assertSame(self::JWKS_URL, (string) $this->httpHistory[0]['request']->getUri());
    }

    public function testLegacyPositionalConstructorStillWorks(): void
    {
        $key = RsaKey::get('a');
        // JWKS already cached: the default HTTP client is never used, so no network call happens
        $this->cacheStore[$this->scopedCacheKey()] = ['keys' => [$key->x5cJwk('kid-a')]];

        $verifier = new Verifier(self::JWKS_URL, self::ISSUER, self::AUDIENCE, $this->cacheManager());

        $claims = $verifier->verifyAndGetClaims($this->token(
            $key,
            'kid-a',
            fn(Builder $b) => $b->issuedAt(new \DateTimeImmutable('-60 seconds'))->expiresAt(new \DateTimeImmutable('+300 seconds'))
        ));

        $this->assertSame('user-1', $claims['sub']);
        $this->assertSame(10.0, $verifier->httpTimeoutSeconds);
        $this->assertSame(0, $verifier->leewaySeconds);
        $this->assertFalse($verifier->requireTimeClaims);
        $this->assertNull($verifier->httpClient);
        $this->assertNull($verifier->clock);
    }

    public function testInvalidSignatureIsRejected(): void
    {
        $verifier = $this->verifier([$this->jwksResponse(RsaKey::get('a')->x5cJwk('kid-a'))]);

        $this->expectException(TokenValidationException::class);
        $verifier->verifyAndGetClaims($this->token(RsaKey::get('b'), 'kid-a'));
    }

    public function testWrongIssuerIsRejected(): void
    {
        $key = RsaKey::get('a');
        $verifier = $this->verifier([$this->jwksResponse($key->x5cJwk('kid-a'))]);

        $this->expectException(TokenValidationException::class);
        $verifier->verifyAndGetClaims($this->token($key, 'kid-a', fn(Builder $b) => $b->issuedBy('https://evil.test/')));
    }

    public function testWrongAudienceIsRejected(): void
    {
        $key = RsaKey::get('a');
        $verifier = $this->verifier([$this->jwksResponse($key->x5cJwk('kid-a'))]);

        $this->expectException(TokenValidationException::class);
        $verifier->verifyAndGetClaims($this->token(
            $key,
            'kid-a',
            fn(Builder $b) => (new Builder(new \Lcobucci\JWT\Encoding\JoseEncoder(), \Lcobucci\JWT\Encoding\ChainedFormatter::default()))
                ->withHeader('kid', 'kid-a')
                ->issuedBy(self::ISSUER)
                ->permittedFor('another-app')
                ->expiresAt($this->now()->modify('+300 seconds'))
        ));
    }

    public function testAudienceFallsBackToSubWhenNotConfigured(): void
    {
        $key = RsaKey::get('a');
        $verifier = new Verifier(
            self::JWKS_URL,
            self::ISSUER,
            httpClient: $this->mockClient([$this->jwksResponse($key->x5cJwk('kid-a'))]),
            clock: $this->clock()
        );

        $claims = $verifier->verifyAndGetClaims($this->token($key, 'kid-a', fn(Builder $b) => $b->permittedFor('user-1')));

        $this->assertSame('user-1', $claims['sub']);
    }

    public function testMissingSubWithoutConfiguredAudienceIsAValidationError(): void
    {
        $key = RsaKey::get('a');
        $verifier = new Verifier(
            self::JWKS_URL,
            self::ISSUER,
            httpClient: $this->mockClient([$this->jwksResponse($key->x5cJwk('kid-a'))]),
            clock: $this->clock()
        );

        $this->expectException(TokenValidationException::class);
        $verifier->verifyAndGetClaims($this->rawToken(['alg' => 'RS256', 'kid' => 'kid-a'], ['iss' => self::ISSUER]));
    }

    public function testModulusExponentKeyVerifiesToken(): void
    {
        $key = RsaKey::get('a');
        $verifier = $this->verifier([$this->jwksResponse($key->modulusExponentJwk('kid-ne'))]);

        $claims = $verifier->verifyAndGetClaims($this->token($key, 'kid-ne'));

        $this->assertSame('user-1', $claims['sub']);
    }

    public function testModulusExponentKeyRejectsTokenSignedWithAnotherKey(): void
    {
        $verifier = $this->verifier([$this->jwksResponse(RsaKey::get('a')->modulusExponentJwk('kid-ne'))]);

        $this->expectException(TokenValidationException::class);
        $verifier->verifyAndGetClaims($this->token(RsaKey::get('b'), 'kid-ne'));
    }

    public function testX5cIsPreferredOverModulusExponent(): void
    {
        $a = RsaKey::get('a');
        $b = RsaKey::get('b');
        // x5c belongs to key A, n/e to key B: a token signed with A must verify
        $jwk = $b->modulusExponentJwk('kid-mixed', ['x5c' => [$a->certificateDerBase64]]);
        $verifier = $this->verifier([$this->jwksResponse($jwk)]);

        $claims = $verifier->verifyAndGetClaims($this->token($a, 'kid-mixed'));

        $this->assertSame('user-1', $claims['sub']);
    }

    public function testKeysWithNonSigUseAreIgnored(): void
    {
        $key = RsaKey::get('a');
        $verifier = $this->verifier([$this->jwksResponse($key->x5cJwk('kid-a', ['use' => 'enc']))]);

        $this->expectException(JwksFormatException::class);
        $this->expectExceptionMessage('Public Key not found in JWKS for KID');
        $verifier->verifyAndGetClaims($this->token($key, 'kid-a'));
    }

    public function testSigKeyIsFoundAfterAnEncKeyWithTheSameKid(): void
    {
        $key = RsaKey::get('a');
        $verifier = $this->verifier([$this->jwksResponse(
            RsaKey::get('b')->x5cJwk('kid-a', ['use' => 'enc']),
            $key->modulusExponentJwk('kid-a')
        )]);

        $this->assertSame('user-1', $verifier->verifyAndGetClaims($this->token($key, 'kid-a'))['sub']);
    }

    public function testKeyWithoutUseIsAccepted(): void
    {
        $key = RsaKey::get('a');
        $jwk = $key->modulusExponentJwk('kid-a');
        unset($jwk['use']);
        $verifier = $this->verifier([$this->jwksResponse($jwk)]);

        $this->assertSame('user-1', $verifier->verifyAndGetClaims($this->token($key, 'kid-a'))['sub']);
    }

    public function testUnsupportedKeyFormatIsRejected(): void
    {
        $verifier = $this->verifier([$this->jwksResponse(['kty' => 'EC', 'kid' => 'kid-ec', 'crv' => 'P-256', 'x' => 'AA', 'y' => 'AA'])]);

        $this->expectException(JwksFormatException::class);
        $this->expectExceptionMessage('Not supported JWKS format key');
        $verifier->verifyAndGetClaims($this->token(RsaKey::get('a'), 'kid-ec'));
    }
}
