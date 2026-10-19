<?php

namespace ZTrippete\JwtVerifier\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use ReflectionProperty;
use ZTrippete\JwtVerifier\Exceptions\JwksFormatException;
use ZTrippete\JwtVerifier\Exceptions\OAuthProviderException;
use ZTrippete\JwtVerifier\Tests\Support\RsaKey;
use ZTrippete\JwtVerifier\Tests\Support\TestCase;
use ZTrippete\JwtVerifier\Verifier;

final class JwksFetchTest extends TestCase
{
    // --- Key rotation -------------------------------------------------------------------

    public function testUnknownKidInCachedJwksTriggersOneRefetch(): void
    {
        $old = RsaKey::get('a');
        $new = RsaKey::get('b');
        $this->cacheStore[$this->scopedCacheKey()] = ['keys' => [$old->x5cJwk('kid-old')]];
        $verifier = $this->verifier([$this->jwksResponse($old->x5cJwk('kid-old'), $new->x5cJwk('kid-new'))], $this->cacheManager());

        $claims = $verifier->verifyAndGetClaims($this->token($new, 'kid-new'));

        $this->assertSame('user-1', $claims['sub']);
        $this->assertCount(1, $this->httpHistory);
        // The refreshed JWKS is stored through the CacheManager
        $this->assertSame(
            ['kid-old', 'kid-new'],
            array_column($this->cacheStore[$this->scopedCacheKey()]['keys'], 'kid')
        );
    }

    public function testUnknownKidAfterRefetchThrowsJwksFormatException(): void
    {
        $key = RsaKey::get('a');
        $this->cacheStore[$this->scopedCacheKey()] = ['keys' => [$key->x5cJwk('kid-old')]];
        $verifier = $this->verifier(
            [$this->jwksResponse($key->x5cJwk('kid-old')), $this->jwksResponse($key->x5cJwk('kid-old'))],
            $this->cacheManager()
        );

        try {
            $verifier->verifyAndGetClaims($this->token($key, 'kid-unknown'));
            $this->fail('JwksFormatException expected');
        } catch (JwksFormatException $e) {
            $this->assertSame('Public Key not found in JWKS for KID', $e->getMessage());
        }

        $this->assertCount(1, $this->httpHistory, 'At most one refetch per verification');
    }

    public function testCacheMissWithUnknownKidFetchesOnlyOnce(): void
    {
        $key = RsaKey::get('a');
        $verifier = $this->verifier(
            [$this->jwksResponse($key->x5cJwk('kid-a')), $this->jwksResponse($key->x5cJwk('kid-a'))],
            $this->cacheManager()
        );

        $this->expectException(JwksFormatException::class);
        try {
            $verifier->verifyAndGetClaims($this->token($key, 'kid-unknown'));
        } finally {
            $this->assertCount(1, $this->httpHistory);
        }
    }

    public function testWithoutCacheManagerUnknownKidFetchesOnlyOnce(): void
    {
        $key = RsaKey::get('a');
        $verifier = $this->verifier([$this->jwksResponse($key->x5cJwk('kid-a')), $this->jwksResponse($key->x5cJwk('kid-a'))]);

        $this->expectException(JwksFormatException::class);
        try {
            $verifier->verifyAndGetClaims($this->token($key, 'kid-unknown'));
        } finally {
            $this->assertCount(1, $this->httpHistory);
        }
    }

    public function testKnownKidInCacheMakesNoHttpCall(): void
    {
        $key = RsaKey::get('a');
        $this->cacheStore[$this->scopedCacheKey()] = ['keys' => [$key->x5cJwk('kid-a')]];
        $verifier = $this->verifier([], $this->cacheManager());

        $verifier->verifyAndGetClaims($this->token($key, 'kid-a'));

        $this->assertCount(0, $this->httpHistory);
    }

    public function testCorruptedCacheEntryIsRefetched(): void
    {
        $key = RsaKey::get('a');
        $this->cacheStore[$this->scopedCacheKey()] = ['unexpected' => true];
        $verifier = $this->verifier([$this->jwksResponse($key->x5cJwk('kid-a'))], $this->cacheManager());

        $verifier->verifyAndGetClaims($this->token($key, 'kid-a'));

        $this->assertCount(1, $this->httpHistory);
        $this->assertArrayHasKey('keys', $this->cacheStore[$this->scopedCacheKey()]);
    }

    // --- Cache key ----------------------------------------------------------------------

    public function testCacheKeyIsScopedToJwksUrl(): void
    {
        $key = RsaKey::get('a');
        $this->verifier([$this->jwksResponse($key->x5cJwk('kid-a'))], $this->cacheManager())
            ->verifyAndGetClaims($this->token($key, 'kid-a'));

        $this->assertSame([$this->scopedCacheKey()], array_keys($this->cacheStore));
        $this->assertArrayNotHasKey('oidc_jwks', $this->cacheStore);
    }

    public function testVerifiersOfDifferentProvidersDoNotShareCacheEntries(): void
    {
        $a = RsaKey::get('a');
        $b = RsaKey::get('b');
        $otherUrl = 'https://other-idp.example.test/jwks';
        $cache = $this->cacheManager();

        $this->verifier([$this->jwksResponse($a->x5cJwk('kid-a'))], $cache)
            ->verifyAndGetClaims($this->token($a, 'kid-a'));

        $other = new Verifier(
            $otherUrl,
            self::ISSUER,
            self::AUDIENCE,
            $cache,
            httpClient: $this->mockClient([$this->jwksResponse($b->x5cJwk('kid-b'))]),
            clock: $this->clock()
        );
        $other->verifyAndGetClaims($this->token($b, 'kid-b'));

        $this->assertNotSame($this->scopedCacheKey(), $this->scopedCacheKey($otherUrl));
        $this->assertSame('kid-a', $this->cacheStore[$this->scopedCacheKey()]['keys'][0]['kid']);
        $this->assertSame('kid-b', $this->cacheStore[$this->scopedCacheKey($otherUrl)]['keys'][0]['kid']);
    }

    // --- HTTP errors --------------------------------------------------------------------

    public function testTimeoutThrowsOAuthProviderException(): void
    {
        $verifier = $this->verifier([
            new ConnectException('cURL error 28: Operation timed out', new Request('GET', self::JWKS_URL)),
        ]);

        $this->expectException(OAuthProviderException::class);
        $this->expectExceptionMessage('timed out');
        $verifier->verifyAndGetClaims($this->token(RsaKey::get('a'), 'kid-a'));
    }

    /**
     * @dataProvider nonSuccessfulStatusProvider
     */
    public function testNonSuccessfulStatusThrowsOAuthProviderException(int $status): void
    {
        $verifier = $this->verifier([new Response($status, [], json_encode(['keys' => []]))]);

        $this->expectException(OAuthProviderException::class);
        $this->expectExceptionMessage('HTTP status ' . $status);
        $verifier->verifyAndGetClaims($this->token(RsaKey::get('a'), 'kid-a'));
    }

    public static function nonSuccessfulStatusProvider(): array
    {
        return ['304' => [304], '404' => [404], '500' => [500], '503' => [503]];
    }

    public function testInvalidJsonThrowsJwksFormatExceptionAndIsNotCached(): void
    {
        $verifier = $this->verifier([new Response(200, [], '<html>oops</html>')], $this->cacheManager());

        try {
            $verifier->verifyAndGetClaims($this->token(RsaKey::get('a'), 'kid-a'));
            $this->fail('JwksFormatException expected');
        } catch (JwksFormatException) {
        }

        $this->assertSame([], $this->cacheStore);
    }

    /**
     * @dataProvider invalidJwksBodyProvider
     */
    public function testBodyWithoutKeysArrayThrowsJwksFormatException(string $body): void
    {
        $verifier = $this->verifier([new Response(200, [], $body)]);

        $this->expectException(JwksFormatException::class);
        $this->expectExceptionMessage('JWKS not valid or without key');
        $verifier->verifyAndGetClaims($this->token(RsaKey::get('a'), 'kid-a'));
    }

    public static function invalidJwksBodyProvider(): array
    {
        return [
            'no keys' => ['{"foo":[]}'],
            'keys not an array' => ['{"keys":"abc"}'],
            'scalar' => ['42'],
        ];
    }

    public function testDefaultClientUsesConfiguredTimeout(): void
    {
        $verifier = new Verifier(self::JWKS_URL, self::ISSUER, httpTimeoutSeconds: 2.5);

        $method = new \ReflectionMethod($verifier, 'httpClient');
        /** @var Client $client */
        $client = $method->invoke($verifier);

        $this->assertInstanceOf(Client::class, $client);
        $this->assertSame(2.5, $client->getConfig('timeout'));
        $this->assertSame(2.5, $client->getConfig('connect_timeout'));
        $this->assertSame($client, $method->invoke($verifier), 'The default client is reused');
    }

    public function testInjectedClientIsUsed(): void
    {
        $client = $this->mockClient();
        $verifier = new Verifier(self::JWKS_URL, self::ISSUER, httpClient: $client);

        $this->assertSame($client, (new \ReflectionMethod($verifier, 'httpClient'))->invoke($verifier));
    }
}
