<?php

namespace ZTrippete\JwtVerifier;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Exception as JwtException;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use Psr\Clock\ClockInterface;
use ZTrippete\JwtVerifier\Exceptions\JwksFormatException;
use ZTrippete\JwtVerifier\Exceptions\OAuthProviderException;
use ZTrippete\JwtVerifier\Exceptions\TokenExpireException;
use ZTrippete\JwtVerifier\Exceptions\TokenFormatException;
use ZTrippete\JwtVerifier\Exceptions\TokenValidationException;

/**
 * @param string $jwksUrl
 * @param string $issuer
 * @param string|null $audience = null
 * @param CacheManager|null $cacheManager = null
 * @param ClientInterface|null $httpClient = null Guzzle client used to fetch the JWKS (default: new Client with $httpTimeoutSeconds)
 * @param float $httpTimeoutSeconds = 10.0 Connect and request timeout of the default client
 * @param int $leewaySeconds = 0 Clock skew tolerated on exp, nbf and iat
 * @param bool $requireTimeClaims = false Reject tokens without exp or iat
 * @param ClockInterface|null $clock = null Clock used for time-based claims (default: system clock)
 */
class Verifier
{
    private const SUPPORTED_ALGORITHM = 'RS256';

    private ?ClientInterface $resolvedHttpClient = null;

    public function __construct(
        readonly string $jwksUrl,
        readonly string $issuer,
        readonly ?string $audience = null,
        readonly ?CacheManager $cacheManager = null,
        readonly ?ClientInterface $httpClient = null,
        readonly float $httpTimeoutSeconds = 10.0,
        readonly int $leewaySeconds = 0,
        readonly bool $requireTimeClaims = false,
        readonly ?ClockInterface $clock = null
    ) {}

    /**
     * This function validate token and return all claims
     *
     * @param string $tokenString
     * @return array
     */
    public function verifyAndGetClaims(string $tokenString): array
    {
        $parser = new Parser(new JoseEncoder());
        try {
            $token = $parser->parse($tokenString);
        } catch (JwtException $e) {
            throw new TokenFormatException('Invalid token format: ' . $e->getMessage(), $e);
        }

        // Validate the header before any JWKS fetch, so a malformed token never reaches the provider
        $kid = $token->headers()->get('kid');
        if (!is_string($kid) || $kid === '') {
            throw new TokenFormatException('Invalid token format: missing or invalid "kid" header');
        }

        if ($token->headers()->get('alg') !== self::SUPPORTED_ALGORITHM) {
            throw new TokenValidationException('Token validation failed: unsupported algorithm, expected ' . self::SUPPORTED_ALGORITHM);
        }

        $publicKey = $this->getPublicKeyFromJwks($kid);

        $audience = $this->audience ?? $token->claims()->get('sub');
        if (!is_string($audience) || $audience === '') {
            throw new TokenValidationException('Token validation failed: no audience configured and token has no "sub" claim');
        }

        $constraints = [
            // Verify that the token was issued by the configured OIDC server
            new IssuedBy($this->issuer),
            // Verify that the token was signed by the configured OIDC server
            new SignedWith(new Sha256(), $publicKey),
            // Verify that the token was issued for this application
            new PermittedFor($audience)
        ];

        // Validate the token against all constraints
        $validator = new Validator();
        try {
            foreach ($constraints as $constraint) {
                $validator->assert($token, $constraint);
            }
        } catch (RequiredConstraintsViolated $e) {
            throw new TokenValidationException('Token validation failed: ' . $e->getMessage(), $e);
        }

        $this->assertTimeClaims($token);

        // If all validations pass, the token is valid
        return $token->claims()->all();
    }

    /**
     * Check exp, nbf and iat against the clock, tolerating $leewaySeconds of clock skew
     *
     * @param UnencryptedToken $token
     * @return void
     */
    protected function assertTimeClaims(UnencryptedToken $token): void
    {
        $claims = $token->claims();
        $expiresAt = $claims->get(RegisteredClaims::EXPIRATION_TIME);
        $notBefore = $claims->get(RegisteredClaims::NOT_BEFORE);
        $issuedAt = $claims->get(RegisteredClaims::ISSUED_AT);

        if ($this->requireTimeClaims) {
            if (!$expiresAt instanceof DateTimeInterface) {
                throw new TokenValidationException('Token validation failed: missing "exp" claim');
            }
            if (!$issuedAt instanceof DateTimeInterface) {
                throw new TokenValidationException('Token validation failed: missing "iat" claim');
            }
        }

        $now = $this->clock?->now() ?? new DateTimeImmutable();
        $leeway = new DateInterval('PT' . max(0, $this->leewaySeconds) . 'S');

        // Check that the token has not expired (a missing exp is accepted unless $requireTimeClaims)
        if ($expiresAt instanceof DateTimeInterface && $expiresAt <= $now->sub($leeway)) {
            throw new TokenExpireException('Token expired');
        }

        if ($notBefore instanceof DateTimeInterface && $notBefore > $now->add($leeway)) {
            throw new TokenValidationException('Token validation failed: token cannot be used yet ("nbf" is in the future)');
        }

        if ($issuedAt instanceof DateTimeInterface && $issuedAt > $now->add($leeway)) {
            throw new TokenValidationException('Token validation failed: token was issued in the future ("iat")');
        }
    }

    /**
     * Function that fetches the public key from the JWKS (cached when a CacheManager is configured).
     * If the kid is not found in a cached JWKS, the JWKS is fetched again once (provider key rotation).
     *
     * @param string $kid
     * @return Key
     */
    protected function getPublicKeyFromJwks(string $kid): Key
    {
        if ($this->cacheManager === null) {
            $jwk = $this->findJwk($this->fetchJwks(), $kid);
        } else {
            $fetched = false;
            $fetchJwksData = function () use (&$fetched): array {
                $fetched = true;
                return $this->fetchJwks();
            };

            $jwk = $this->findJwk($this->cacheManager->remember($this->cacheKey(), $fetchJwksData), $kid);

            // Unknown kid in a cached JWKS: the provider may have rotated its keys
            if ($jwk === null && !$fetched) {
                $jwk = $this->findJwk($this->cacheManager->refresh($this->cacheKey(), $fetchJwksData), $kid);
            }
        }

        if ($jwk === null) {
            throw new JwksFormatException('Public Key not found in JWKS for KID');
        }

        return InMemory::plainText(JwkConverter::toPem($jwk));
    }

    /**
     * Cache key scoped to the JWKS URL, so verifiers of different providers can share the same store
     *
     * @return string
     */
    protected function cacheKey(): string
    {
        return 'oidc_jwks:' . hash('sha256', $this->jwksUrl);
    }

    /**
     * Fetch and decode the JWKS from the provider
     *
     * @return array
     */
    protected function fetchJwks(): array
    {
        try {
            $response = $this->httpClient()->request('GET', $this->jwksUrl, [
                'http_errors' => false,
                'headers' => ['Accept' => 'application/json'],
            ]);
        } catch (GuzzleException $e) {
            throw new OAuthProviderException('Error during fetch JWKS from provider: ' . $e->getMessage(), $e);
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new OAuthProviderException('Error during fetch JWKS from provider: HTTP status ' . $status);
        }

        try {
            $jwksData = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new JwksFormatException('JWKS not valid JSON: ' . $e->getMessage(), $e);
        }

        if (!is_array($jwksData) || !isset($jwksData['keys']) || !is_array($jwksData['keys'])) {
            throw new JwksFormatException('JWKS not valid or without key');
        }

        return $jwksData;
    }

    /**
     * Find the signing key with the given kid, ignoring keys whose "use" is not "sig"
     *
     * @param array $jwksData
     * @param string $kid
     * @return array|null
     */
    private function findJwk(array $jwksData, string $kid): ?array
    {
        if (!isset($jwksData['keys']) || !is_array($jwksData['keys'])) {
            return null;
        }

        foreach ($jwksData['keys'] as $key) {
            if (!is_array($key) || ($key['kid'] ?? null) !== $kid) {
                continue;
            }
            if (isset($key['use']) && $key['use'] !== 'sig') {
                continue;
            }
            return $key;
        }

        return null;
    }

    private function httpClient(): ClientInterface
    {
        return $this->resolvedHttpClient ??= $this->httpClient ?? new Client([
            'timeout' => $this->httpTimeoutSeconds,
            'connect_timeout' => $this->httpTimeoutSeconds,
        ]);
    }
}
