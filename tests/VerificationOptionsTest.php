<?php

namespace ZTrippete\JwtVerifier\Tests;

use Closure;
use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\JWT\Token\Builder;
use ZTrippete\JwtVerifier\Exceptions\TokenValidationException;
use ZTrippete\JwtVerifier\Tests\Support\RsaKey;
use ZTrippete\JwtVerifier\Tests\Support\TestCase;
use ZTrippete\JwtVerifier\VerificationOptions;

final class VerificationOptionsTest extends TestCase
{
    private function verify(string $token, ?VerificationOptions $options = null, array $verifierOptions = []): array
    {
        $verifier = $this->verifier([$this->jwksResponse(RsaKey::get('a')->x5cJwk('kid-a'))], null, $verifierOptions);

        return $verifier->verifyAndGetClaims($token, $options);
    }

    private function signed(?Closure $customize = null): string
    {
        return $this->token(RsaKey::get('a'), 'kid-a', $customize);
    }

    private function assertRejected(string $token, VerificationOptions $options, string $message): void
    {
        try {
            $this->verify($token, $options);
            $this->fail('TokenValidationException expected');
        } catch (TokenValidationException $e) {
            $this->assertStringContainsString($message, $e->getMessage());
        }
    }

    /**
     * Valid signed token (iss, aud, iat, exp, sub=user-1) with extra payload entries
     */
    private function signedPayload(array $extra, array $header = []): string
    {
        return $this->signedRawToken(RsaKey::get('a'), $header + ['alg' => 'RS256', 'kid' => 'kid-a', 'typ' => 'JWT'], $extra + [
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'sub' => 'user-1',
            'iat' => self::NOW - 60,
            'exp' => self::NOW + 300,
        ]);
    }

    // --- Backward compatibility ---------------------------------------------------------

    public function testWithoutOptionsReturnsTheSameClaimsAs230(): void
    {
        $token = $this->signed();
        $expected = [
            'iss' => self::ISSUER,
            'aud' => [self::AUDIENCE],
            'sub' => 'user-1',
            'iat' => $this->now()->modify('-60 seconds'),
            'exp' => $this->now()->modify('+300 seconds'),
        ];

        foreach ([null, new VerificationOptions()] as $options) {
            $claims = $this->verify($token, $options);
            ksort($claims);
            ksort($expected);
            $this->assertEquals($expected, $claims);
            $this->assertInstanceOf(DateTimeImmutable::class, $claims['exp']);
            $this->assertInstanceOf(DateTimeImmutable::class, $claims['iat']);
        }
    }

    // --- typ ----------------------------------------------------------------------------

    /**
     * @dataProvider acceptedTypeProvider
     */
    public function testExpectedTypeAccepted(string $typ, string $expected): void
    {
        $claims = $this->verify(
            $this->signed(fn(Builder $b) => $b->withHeader('typ', $typ)),
            new VerificationOptions(expectedType: $expected)
        );

        $this->assertSame('user-1', $claims['sub']);
    }

    public static function acceptedTypeProvider(): array
    {
        return [
            'exact' => ['at+jwt', 'at+jwt'],
            'application prefix in token' => ['application/at+jwt', 'at+jwt'],
            'application prefix in expected' => ['at+jwt', 'application/at+jwt'],
            'uppercase' => ['AT+JWT', 'at+jwt'],
            'mixed case prefix' => ['Application/At+JWT', 'at+jwt'],
        ];
    }

    /**
     * @dataProvider rejectedTypeHeaderProvider
     */
    public function testExpectedTypeRejectedWithoutHttpCall(array $header): void
    {
        $verifier = $this->verifier([$this->jwksResponse(RsaKey::get('a')->x5cJwk('kid-a'))], $this->cacheManager());

        try {
            $verifier->verifyAndGetClaims($this->rawToken($header), new VerificationOptions(expectedType: 'at+jwt'));
            $this->fail('TokenValidationException expected');
        } catch (TokenValidationException $e) {
            $this->assertStringContainsString('"typ"', $e->getMessage());
        }

        $this->assertCount(0, $this->httpHistory);
    }

    public static function rejectedTypeHeaderProvider(): array
    {
        return [
            'missing typ' => [['alg' => 'RS256', 'kid' => 'kid-a']],
            'JWT' => [['alg' => 'RS256', 'kid' => 'kid-a', 'typ' => 'JWT']],
            'other type' => [['alg' => 'RS256', 'kid' => 'kid-a', 'typ' => 'application/jwt']],
            'suffix' => [['alg' => 'RS256', 'kid' => 'kid-a', 'typ' => 'at+jwt+x']],
            'non string' => [['alg' => 'RS256', 'kid' => 'kid-a', 'typ' => 1]],
        ];
    }

    public function testExpectedTypeJwtRejectsMissingTyp(): void
    {
        // The parser defaults a missing typ to "JWT": the check must read the raw header
        $verifier = $this->verifier();

        $this->expectException(TokenValidationException::class);
        $verifier->verifyAndGetClaims($this->rawToken(['alg' => 'RS256', 'kid' => 'kid-a']), new VerificationOptions(expectedType: 'JWT'));
    }

    // --- nonce --------------------------------------------------------------------------

    public function testNonceAccepted(): void
    {
        $claims = $this->verify(
            $this->signed(fn(Builder $b) => $b->withClaim('nonce', 'n-123')),
            new VerificationOptions(expectedNonce: 'n-123')
        );

        $this->assertSame('n-123', $claims['nonce']);
    }

    public function testNonceMissingRejected(): void
    {
        $this->assertRejected($this->signed(), new VerificationOptions(expectedNonce: 'n-123'), '"nonce"');
    }

    public function testNonceMismatchRejected(): void
    {
        $this->assertRejected(
            $this->signed(fn(Builder $b) => $b->withClaim('nonce', 'n-456')),
            new VerificationOptions(expectedNonce: 'n-123'),
            '"nonce"'
        );
    }

    public function testNonNonceStringRejected(): void
    {
        $this->assertRejected(
            $this->signed(fn(Builder $b) => $b->withClaim('nonce', 123)),
            new VerificationOptions(expectedNonce: '123'),
            '"nonce"'
        );
    }

    // --- azp (idToken) ------------------------------------------------------------------

    public function testIdTokenWithoutAzpAndSingleAudienceAccepted(): void
    {
        $claims = $this->verify($this->signed(), new VerificationOptions(idToken: true));

        $this->assertSame([self::AUDIENCE], $claims['aud']);
    }

    public function testIdTokenWithoutAzpAndMultipleAudiencesRejected(): void
    {
        $this->assertRejected(
            $this->signed(fn(Builder $b) => $b->permittedFor('other-app')),
            new VerificationOptions(idToken: true),
            '"azp"'
        );
    }

    public function testMultipleAudiencesWithoutAzpAcceptedWhenNotIdToken(): void
    {
        $claims = $this->verify($this->signed(fn(Builder $b) => $b->permittedFor('other-app')), new VerificationOptions());

        $this->assertSame([self::AUDIENCE, 'other-app'], $claims['aud']);
    }

    public function testIdTokenWithAzpEqualToAudienceAccepted(): void
    {
        $claims = $this->verify(
            $this->signed(fn(Builder $b) => $b->permittedFor('other-app')->withClaim('azp', self::AUDIENCE)),
            new VerificationOptions(idToken: true)
        );

        $this->assertSame(self::AUDIENCE, $claims['azp']);
    }

    public function testIdTokenWithAzpDifferentFromAudienceRejected(): void
    {
        $this->assertRejected(
            $this->signed(fn(Builder $b) => $b->withClaim('azp', 'other-app')),
            new VerificationOptions(idToken: true),
            '"azp"'
        );
    }

    public function testIdTokenWithNonStringAzpRejected(): void
    {
        $this->assertRejected(
            $this->signed(fn(Builder $b) => $b->withClaim('azp', [self::AUDIENCE])),
            new VerificationOptions(idToken: true),
            '"azp"'
        );
    }

    // --- scopes -------------------------------------------------------------------------

    /**
     * @dataProvider acceptedScopeProvider
     */
    public function testRequiredScopesAccepted(mixed $scope, array $required): void
    {
        $claims = $this->verify(
            $this->signed(fn(Builder $b) => $b->withClaim('scope', $scope)),
            new VerificationOptions(requiredScopes: $required)
        );

        $this->assertSame($scope, $claims['scope']);
    }

    public static function acceptedScopeProvider(): array
    {
        return [
            'string' => ['openid profile api', ['api', 'openid']],
            'string with extra spaces' => ['  openid   api ', ['api']],
            'list' => [['openid', 'api'], ['api', 'openid']],
            'list of space-delimited items' => [['openid profile', 'api step-up'], ['step-up', 'profile']],
        ];
    }

    /**
     * @dataProvider rejectedScopeProvider
     */
    public function testRequiredScopesRejected(mixed $scope, array $required): void
    {
        $this->assertRejected(
            $this->signed(fn(Builder $b) => $b->withClaim('scope', $scope)),
            new VerificationOptions(requiredScopes: $required),
            'scope'
        );
    }

    public static function rejectedScopeProvider(): array
    {
        return [
            'one missing' => ['openid profile', ['openid', 'api']],
            'partial token' => ['openid step-up-extra', ['step-up']],
            'partial token in list' => [['openid', 'step-up-extra'], ['step-up']],
            'prefix of a token' => ['api', ['ap']],
            'empty string' => ['', ['api']],
            'blank string' => ['   ', ['api']],
            'blank item' => [['api', ' '], ['api']],
            'empty item' => [['api', ''], ['api']],
            'non string item' => [['api', 42], ['api']],
            'empty list' => [[], ['api']],
            'object' => [['a' => 'api'], ['api']],
            'non string claim' => [42, ['api']],
        ];
    }

    public function testRequiredScopesWithMissingClaimRejected(): void
    {
        $this->assertRejected($this->signed(), new VerificationOptions(requiredScopes: ['api']), '"scope"');
    }

    public function testScopeClaimIsNotCheckedWithoutRequiredScopes(): void
    {
        $claims = $this->verify($this->signed(fn(Builder $b) => $b->withClaim('scope', 42)), new VerificationOptions());

        $this->assertSame(42, $claims['scope']);
    }

    // --- client_id / sub / claimsEqualIfPresent -----------------------------------------

    public function testClientIdAccepted(): void
    {
        $claims = $this->verify(
            $this->signed(fn(Builder $b) => $b->withClaim('client_id', 'core-api-client')),
            new VerificationOptions(expectedClientId: 'core-api-client')
        );

        $this->assertSame('core-api-client', $claims['client_id']);
    }

    /**
     * @dataProvider rejectedClientIdProvider
     */
    public function testClientIdRejected(?Closure $customize): void
    {
        $this->assertRejected($this->signed($customize), new VerificationOptions(expectedClientId: 'core-api-client'), '"client_id"');
    }

    public static function rejectedClientIdProvider(): array
    {
        return [
            'missing' => [null],
            'mismatch' => [fn(Builder $b) => $b->withClaim('client_id', 'other-client')],
            'non string' => [fn(Builder $b) => $b->withClaim('client_id', ['core-api-client'])],
        ];
    }

    public function testRequireSubjectAccepted(): void
    {
        $this->assertSame('user-1', $this->verify($this->signed(), new VerificationOptions(requireSubject: true))['sub']);
    }

    /**
     * @dataProvider rejectedSubjectProvider
     */
    public function testRequireSubjectRejected(array $payload): void
    {
        $this->assertRejected($this->signedPayload($payload), new VerificationOptions(requireSubject: true), '"sub"');
    }

    public static function rejectedSubjectProvider(): array
    {
        return [
            'blank' => [['sub' => '   ']],
            'empty' => [['sub' => '']],
            'non string' => [['sub' => 42]],
        ];
    }

    public function testRequireSubjectWithMissingSubRejected(): void
    {
        $token = $this->signedRawToken(RsaKey::get('a'), ['alg' => 'RS256', 'kid' => 'kid-a'], [
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'exp' => self::NOW + 300,
        ]);

        $this->assertRejected($token, new VerificationOptions(requireSubject: true), '"sub"');
    }

    public function testClaimEqualIfPresentAcceptedWhenAbsent(): void
    {
        $claims = $this->verify($this->signed(), new VerificationOptions(claimsEqualIfPresent: ['oi_prst' => 'core-api-client']));

        $this->assertArrayNotHasKey('oi_prst', $claims);
    }

    public function testClaimEqualIfPresentAcceptedWhenEqual(): void
    {
        $claims = $this->verify(
            $this->signed(fn(Builder $b) => $b->withClaim('oi_prst', 'core-api-client')),
            new VerificationOptions(claimsEqualIfPresent: ['oi_prst' => 'core-api-client'])
        );

        $this->assertSame('core-api-client', $claims['oi_prst']);
    }

    /**
     * @dataProvider rejectedPresenterProvider
     */
    public function testClaimEqualIfPresentRejectedWhenDifferent(mixed $value): void
    {
        $this->assertRejected(
            $this->signed(fn(Builder $b) => $b->withClaim('oi_prst', $value)),
            new VerificationOptions(claimsEqualIfPresent: ['oi_prst' => 'core-api-client']),
            '"oi_prst"'
        );
    }

    public static function rejectedPresenterProvider(): array
    {
        return ['other client' => ['other-client'], 'null' => [null], 'non string' => [['core-api-client']]];
    }

    // --- Option combination -------------------------------------------------------------

    public function testAllOptionsTogether(): void
    {
        $claims = $this->verify(
            $this->signed(fn(Builder $b) => $b
                ->withHeader('typ', 'at+jwt')
                ->withClaim('nonce', 'n-1')
                ->withClaim('azp', self::AUDIENCE)
                ->withClaim('scope', 'openid api step-up')
                ->withClaim('client_id', 'core-api-client')
                ->withClaim('oi_prst', 'core-api-client')),
            new VerificationOptions(
                expectedType: 'at+jwt',
                expectedNonce: 'n-1',
                idToken: true,
                requiredScopes: ['api', 'step-up'],
                expectedClientId: 'core-api-client',
                requireSubject: true,
                claimsEqualIfPresent: ['oi_prst' => 'core-api-client'],
            )
        );

        $this->assertSame('user-1', $claims['sub']);
    }

    public function testOptionChecksRunAfterSignatureValidation(): void
    {
        // Wrong signature and wrong nonce: the signature failure is reported
        $verifier = $this->verifier([$this->jwksResponse(RsaKey::get('a')->x5cJwk('kid-a'))]);

        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('signature');
        $verifier->verifyAndGetClaims($this->token(RsaKey::get('b'), 'kid-a'), new VerificationOptions(expectedNonce: 'x'));
    }

    // --- aud values (always on) ---------------------------------------------------------

    public function testNonStringAudienceValueRejected(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('"aud"');
        $this->verify($this->signedPayload(['aud' => [self::AUDIENCE, 123]]));
    }

    public function testAudienceAsStringAccepted(): void
    {
        $this->assertSame([self::AUDIENCE], $this->verify($this->signedPayload(['aud' => self::AUDIENCE]))['aud']);
    }

    // --- rawTimeClaims ------------------------------------------------------------------

    public function testRawTimeClaimsReturnsIntegers(): void
    {
        $claims = $this->verify(
            $this->signed(fn(Builder $b) => $b->canOnlyBeUsedAfter($this->now()->modify('-30 seconds'))),
            null,
            ['rawTimeClaims' => true]
        );

        $this->assertSame(self::NOW + 300, $claims['exp']);
        $this->assertSame(self::NOW - 60, $claims['iat']);
        $this->assertSame(self::NOW - 30, $claims['nbf']);
        $this->assertSame([self::AUDIENCE], $claims['aud']);
        $this->assertSame('user-1', $claims['sub']);
    }

    public function testRawTimeClaimsWithMissingTimeClaims(): void
    {
        $token = $this->signedRawToken(RsaKey::get('a'), ['alg' => 'RS256', 'kid' => 'kid-a'], [
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'sub' => 'user-1',
        ]);

        $claims = $this->verify($token, null, ['rawTimeClaims' => true]);

        $this->assertArrayNotHasKey('exp', $claims);
        $this->assertArrayNotHasKey('iat', $claims);
        $this->assertArrayNotHasKey('nbf', $claims);
    }

    // --- Option validation --------------------------------------------------------------

    /**
     * @dataProvider invalidOptionsProvider
     */
    public function testInvalidOptionsAreRejected(array $arguments): void
    {
        $this->expectException(InvalidArgumentException::class);
        new VerificationOptions(...$arguments);
    }

    public static function invalidOptionsProvider(): array
    {
        return [
            'blank type' => [['expectedType' => ' ']],
            'blank nonce' => [['expectedNonce' => '']],
            'blank client id' => [['expectedClientId' => '']],
            'scope with space' => [['requiredScopes' => ['openid api']]],
            'blank scope' => [['requiredScopes' => ['']]],
            'non string scope' => [['requiredScopes' => [1]]],
            'non string claim value' => [['claimsEqualIfPresent' => ['oi_prst' => 1]]],
            'list instead of map' => [['claimsEqualIfPresent' => ['core-api-client']]],
        ];
    }
}
