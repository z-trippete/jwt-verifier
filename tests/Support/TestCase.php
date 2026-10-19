<?php

namespace ZTrippete\JwtVerifier\Tests\Support;

use Closure;
use DateTimeImmutable;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use PHPUnit\Framework\TestCase as BaseTestCase;
use ZTrippete\JwtVerifier\CacheManager;
use ZTrippete\JwtVerifier\Verifier;

abstract class TestCase extends BaseTestCase
{
    protected const JWKS_URL = 'https://idp.example.test/.well-known/jwks';
    protected const ISSUER = 'https://idp.example.test/';
    protected const AUDIENCE = 'core-api';
    protected const NOW = 1_700_000_000;

    /** @var array<int, array{request: \Psr\Http\Message\RequestInterface}> */
    protected array $httpHistory = [];

    /** @var array<string, array> */
    protected array $cacheStore = [];

    protected function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@' . self::NOW);
    }

    protected function clock(): FrozenClock
    {
        return new FrozenClock($this->now());
    }

    /**
     * Guzzle client answering with the queued responses/exceptions, recording every request
     */
    protected function mockClient(array $queue = []): Client
    {
        $stack = HandlerStack::create(new MockHandler($queue));
        $stack->push(Middleware::history($this->httpHistory));

        return new Client(['handler' => $stack]);
    }

    protected function jwksResponse(array ...$keys): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode(['keys' => $keys]));
    }

    protected function cacheManager(): CacheManager
    {
        return new CacheManager(
            fn(string $key) => $this->cacheStore[$key] ?? null,
            function (string $key, array $data): void {
                $this->cacheStore[$key] = $data;
            }
        );
    }

    protected function verifier(array $httpQueue = [], ?CacheManager $cacheManager = null, array $options = []): Verifier
    {
        return new Verifier(
            self::JWKS_URL,
            self::ISSUER,
            self::AUDIENCE,
            $cacheManager,
            httpClient: $this->mockClient($httpQueue),
            leewaySeconds: $options['leewaySeconds'] ?? 0,
            requireTimeClaims: $options['requireTimeClaims'] ?? false,
            clock: $this->clock()
        );
    }

    /**
     * Build an RS256 token signed with the given key; $customize receives and returns the Builder
     */
    protected function token(RsaKey $key, string $kid, ?Closure $customize = null): string
    {
        $builder = (new Builder(new JoseEncoder(), ChainedFormatter::default()))
            ->withHeader('kid', $kid)
            ->issuedBy(self::ISSUER)
            ->permittedFor(self::AUDIENCE)
            ->relatedTo('user-1')
            ->issuedAt($this->now()->modify('-60 seconds'))
            ->expiresAt($this->now()->modify('+300 seconds'));

        if ($customize !== null) {
            $builder = $customize($builder);
        }

        return $builder->getToken(new Sha256(), InMemory::plainText($key->privatePem))->toString();
    }

    /**
     * Build a token with arbitrary header/payload and a dummy signature
     */
    protected function rawToken(array $header, array $payload = ['iss' => self::ISSUER]): string
    {
        return RsaKey::base64Url(json_encode($header)) . '.' .
            RsaKey::base64Url(json_encode($payload)) . '.' .
            RsaKey::base64Url('signature');
    }

    protected function scopedCacheKey(string $jwksUrl = self::JWKS_URL): string
    {
        return 'oidc_jwks:' . hash('sha256', $jwksUrl);
    }
}
