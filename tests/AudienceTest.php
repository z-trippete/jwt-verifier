<?php

namespace ZTrippete\JwtVerifier\Tests;

use InvalidArgumentException;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use ZTrippete\JwtVerifier\Exceptions\TokenValidationException;
use ZTrippete\JwtVerifier\Tests\Support\RsaKey;
use ZTrippete\JwtVerifier\Tests\Support\TestCase;
use ZTrippete\JwtVerifier\VerificationOptions;
use ZTrippete\JwtVerifier\Verifier;

final class AudienceTest extends TestCase
{
    private function verifierFor(string|array|null $audience): Verifier
    {
        return new Verifier(
            self::JWKS_URL,
            self::ISSUER,
            $audience,
            httpClient: $this->mockClient([$this->jwksResponse(RsaKey::get('a')->x5cJwk('kid-a'))]),
            clock: $this->clock()
        );
    }

    /**
     * Signed token whose aud is exactly the given list (and optional extra claims)
     */
    private function tokenFor(array $aud, array $claims = []): string
    {
        return $this->token(RsaKey::get('a'), 'kid-a', function () use ($aud, $claims) {
            $builder = (new Builder(new JoseEncoder(), ChainedFormatter::default()))
                ->withHeader('kid', 'kid-a')
                ->issuedBy(self::ISSUER)
                ->permittedFor(...$aud)
                ->relatedTo('user-1')
                ->expiresAt($this->now()->modify('+300 seconds'));
            foreach ($claims as $name => $value) {
                $builder = $builder->withClaim($name, $value);
            }
            return $builder;
        });
    }

    public function testStringAudienceStillWorks(): void
    {
        $this->assertSame(['api-a'], $this->verifierFor('api-a')->verifyAndGetClaims($this->tokenFor(['api-a']))['aud']);
    }

    /**
     * @dataProvider acceptedAudienceProvider
     */
    public function testTokenWithAnyConfiguredAudienceIsAccepted(array $configured, array $tokenAud): void
    {
        $claims = $this->verifierFor($configured)->verifyAndGetClaims($this->tokenFor($tokenAud));

        $this->assertSame($tokenAud, $claims['aud']);
    }

    public static function acceptedAudienceProvider(): array
    {
        return [
            'single item list' => [['api-a'], ['api-a']],
            'first configured' => [['api-a', 'api-b'], ['api-a']],
            'second configured' => [['api-a', 'api-b'], ['api-b']],
            'token with several audiences' => [['api-a', 'api-b'], ['other', 'api-b']],
        ];
    }

    /**
     * @dataProvider rejectedAudienceProvider
     */
    public function testTokenWithoutAnyConfiguredAudienceIsRejected(string|array $configured): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('audience');
        $this->verifierFor($configured)->verifyAndGetClaims($this->tokenFor(['other']));
    }

    public static function rejectedAudienceProvider(): array
    {
        return ['string' => ['api-a'], 'list' => [['api-a', 'api-b']]];
    }

    public function testSingleItemListBehavesLikeString(): void
    {
        $messages = [];
        foreach (['api-a', ['api-a']] as $configured) {
            try {
                $this->verifierFor($configured)->verifyAndGetClaims($this->tokenFor(['other']));
            } catch (TokenValidationException $e) {
                $messages[] = $e->getMessage();
            }
        }

        $this->assertCount(2, $messages);
        $this->assertSame($messages[0], $messages[1]);
    }

    public function testAzpMayBeAnyConfiguredAudience(): void
    {
        $claims = $this->verifierFor(['api-a', 'api-b'])->verifyAndGetClaims(
            $this->tokenFor(['api-a', 'api-b'], ['azp' => 'api-b']),
            new VerificationOptions(idToken: true)
        );

        $this->assertSame('api-b', $claims['azp']);
    }

    public function testAzpNotInConfiguredAudiencesIsRejected(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('"azp"');
        $this->verifierFor(['api-a', 'api-b'])->verifyAndGetClaims(
            $this->tokenFor(['api-a'], ['azp' => 'other']),
            new VerificationOptions(idToken: true)
        );
    }

    public function testAzpConfiguredButNotInTokenAudIsRejected(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('"azp" claim is not contained in "aud"');
        $this->verifierFor(['api-a', 'api-b'])->verifyAndGetClaims(
            $this->tokenFor(['api-a', 'other'], ['azp' => 'api-b']),
            new VerificationOptions(idToken: true)
        );
    }

    public function testIdTokenWithMultipleAudiencesAndNoAzpIsRejectedWithAudienceList(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('"azp" claim is required');
        $this->verifierFor(['api-a', 'api-b'])->verifyAndGetClaims(
            $this->tokenFor(['api-a', 'api-b']),
            new VerificationOptions(idToken: true)
        );
    }

    /**
     * @dataProvider invalidAudienceConfigProvider
     */
    public function testInvalidAudienceListIsRejectedAtConstruction(array $audience): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Verifier(self::JWKS_URL, self::ISSUER, $audience);
    }

    public static function invalidAudienceConfigProvider(): array
    {
        return [
            'empty' => [[]],
            'blank item' => [['api-a', ' ']],
            'non string item' => [['api-a', 1]],
            'associative array' => [['main' => 'api-a']],
            'non sequential keys' => [[1 => 'api-a', 2 => 'api-b']],
        ];
    }
}
