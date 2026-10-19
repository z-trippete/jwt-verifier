<?php

namespace ZTrippete\JwtVerifier\Tests;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use ZTrippete\JwtVerifier\Exceptions\TokenExpireException;
use ZTrippete\JwtVerifier\Exceptions\TokenValidationException;
use ZTrippete\JwtVerifier\Tests\Support\RsaKey;
use ZTrippete\JwtVerifier\Tests\Support\TestCase;

final class TimeClaimsTest extends TestCase
{
    private function verify(string $token, array $options = []): array
    {
        $verifier = $this->verifier([$this->jwksResponse(RsaKey::get('a')->x5cJwk('kid-a'))], null, $options);

        return $verifier->verifyAndGetClaims($token);
    }

    private function at(int $offsetSeconds): DateTimeImmutable
    {
        return $this->now()->modify(sprintf('%+d seconds', $offsetSeconds));
    }

    /**
     * Token without any time claim, so each test adds only what it needs
     */
    private function tokenWith(callable $customize): string
    {
        return $this->token(RsaKey::get('a'), 'kid-a', fn() => $customize(
            (new Builder(new JoseEncoder(), ChainedFormatter::default()))
                ->withHeader('kid', 'kid-a')
                ->issuedBy(self::ISSUER)
                ->permittedFor(self::AUDIENCE)
                ->relatedTo('user-1')
        ));
    }

    // --- exp ----------------------------------------------------------------------------

    public function testExpiredTokenWithoutLeewayThrows(): void
    {
        $this->expectException(TokenExpireException::class);
        $this->verify($this->tokenWith(fn(Builder $b) => $b->expiresAt($this->at(-1))));
    }

    public function testTokenExpiringExactlyNowIsExpired(): void
    {
        $this->expectException(TokenExpireException::class);
        $this->verify($this->tokenWith(fn(Builder $b) => $b->expiresAt($this->at(0))));
    }

    public function testRecentlyExpiredTokenIsAcceptedWithinLeeway(): void
    {
        $claims = $this->verify($this->tokenWith(fn(Builder $b) => $b->expiresAt($this->at(-30))), ['leewaySeconds' => 60]);

        $this->assertSame('user-1', $claims['sub']);
    }

    public function testExpiredTokenBeyondLeewayThrows(): void
    {
        $this->expectException(TokenExpireException::class);
        $this->verify($this->tokenWith(fn(Builder $b) => $b->expiresAt($this->at(-120))), ['leewaySeconds' => 60]);
    }

    public function testExpiredExactlyAtLeewayBoundaryThrows(): void
    {
        $this->expectException(TokenExpireException::class);
        $this->verify($this->tokenWith(fn(Builder $b) => $b->expiresAt($this->at(-60))), ['leewaySeconds' => 60]);
    }

    // --- nbf ----------------------------------------------------------------------------

    public function testFutureNbfThrows(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('nbf');
        $this->verify($this->tokenWith(fn(Builder $b) => $b->canOnlyBeUsedAfter($this->at(10))->expiresAt($this->at(300))));
    }

    public function testFutureNbfWithinLeewayIsAccepted(): void
    {
        $claims = $this->verify(
            $this->tokenWith(fn(Builder $b) => $b->canOnlyBeUsedAfter($this->at(30))->expiresAt($this->at(300))),
            ['leewaySeconds' => 60]
        );

        $this->assertSame('user-1', $claims['sub']);
    }

    public function testFutureNbfBeyondLeewayThrows(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->verify(
            $this->tokenWith(fn(Builder $b) => $b->canOnlyBeUsedAfter($this->at(120))->expiresAt($this->at(300))),
            ['leewaySeconds' => 60]
        );
    }

    public function testPastNbfIsAccepted(): void
    {
        $claims = $this->verify($this->tokenWith(fn(Builder $b) => $b->canOnlyBeUsedAfter($this->at(-10))->expiresAt($this->at(300))));

        $this->assertSame('user-1', $claims['sub']);
    }

    // --- iat ----------------------------------------------------------------------------

    public function testFutureIatThrows(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('iat');
        $this->verify($this->tokenWith(fn(Builder $b) => $b->issuedAt($this->at(10))->expiresAt($this->at(300))));
    }

    public function testFutureIatWithinLeewayIsAccepted(): void
    {
        $claims = $this->verify(
            $this->tokenWith(fn(Builder $b) => $b->issuedAt($this->at(30))->expiresAt($this->at(300))),
            ['leewaySeconds' => 60]
        );

        $this->assertSame('user-1', $claims['sub']);
    }

    public function testFutureIatBeyondLeewayThrows(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->verify(
            $this->tokenWith(fn(Builder $b) => $b->issuedAt($this->at(120))->expiresAt($this->at(300))),
            ['leewaySeconds' => 60]
        );
    }

    // --- missing claims -----------------------------------------------------------------

    public function testMissingExpIsAcceptedByDefault(): void
    {
        // Runs with failOnWarning: no PHP warning must be raised for the missing claim
        $claims = $this->verify($this->tokenWith(fn(Builder $b) => $b->issuedAt($this->at(-10))));

        $this->assertArrayNotHasKey('exp', $claims);
    }

    public function testMissingExpIsRejectedWhenTimeClaimsAreRequired(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('"exp"');
        $this->verify($this->tokenWith(fn(Builder $b) => $b->issuedAt($this->at(-10))), ['requireTimeClaims' => true]);
    }

    public function testMissingIatIsRejectedWhenTimeClaimsAreRequired(): void
    {
        $this->expectException(TokenValidationException::class);
        $this->expectExceptionMessage('"iat"');
        $this->verify($this->tokenWith(fn(Builder $b) => $b->expiresAt($this->at(300))), ['requireTimeClaims' => true]);
    }

    public function testTokenWithAllTimeClaimsPassesWhenRequired(): void
    {
        $claims = $this->verify(
            $this->tokenWith(fn(Builder $b) => $b->issuedAt($this->at(-10))->expiresAt($this->at(300))),
            ['requireTimeClaims' => true]
        );

        $this->assertSame('user-1', $claims['sub']);
    }
}
