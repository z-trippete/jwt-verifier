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
 * @param bool $rawTimeClaims = false Return exp, iat and nbf as integer Unix timestamps instead of DateTimeImmutable
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
        readonly ?ClockInterface $clock = null,
        readonly bool $rawTimeClaims = false
    ) {}

    /**
     * This function validate token and return all claims
     *
     * @param string $tokenString
     * @param VerificationOptions|null $options Optional per-token checks
     * @return array
     */
    public function verifyAndGetClaims(string $tokenString, ?VerificationOptions $options = null): array
    {
        $encoder = new JoseEncoder();
        $parser = new Parser($encoder);
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

        if ($options?->expectedType !== null) {
            // Read "typ" from the raw header: the parser defaults a missing "typ" to "JWT"
            $rawHeader = $encoder->jsonDecode($encoder->base64UrlDecode(strstr($tokenString, '.', true)));
            $this->assertExpectedType($rawHeader['typ'] ?? null, $options->expectedType);
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

        foreach ($token->claims()->get(RegisteredClaims::AUDIENCE, []) as $value) {
            if (!is_string($value)) {
                throw new TokenValidationException('Token validation failed: "aud" must contain only strings');
            }
        }

        $this->assertTimeClaims($token);

        if ($options !== null) {
            $this->assertOptions($token, $options, $audience);
        }

        // If all validations pass, the token is valid
        $claims = $token->claims()->all();

        if ($this->rawTimeClaims) {
            foreach ([RegisteredClaims::EXPIRATION_TIME, RegisteredClaims::ISSUED_AT, RegisteredClaims::NOT_BEFORE] as $name) {
                if (isset($claims[$name]) && $claims[$name] instanceof DateTimeInterface) {
                    $claims[$name] = $claims[$name]->getTimestamp();
                }
            }
        }

        return $claims;
    }

    /**
     * "typ" header check (RFC 9068 / RFC 7515): case-insensitive, optional "application/" prefix
     *
     * @param mixed $type
     * @param string $expectedType
     * @return void
     */
    protected function assertExpectedType(mixed $type, string $expectedType): void
    {
        $normalize = fn(string $value): string => preg_replace('#^application/#', '', strtolower(trim($value)));

        if (!is_string($type) || !hash_equals($normalize($expectedType), $normalize($type))) {
            throw new TokenValidationException('Token validation failed: "typ" header is missing or not "' . $expectedType . '"');
        }
    }

    /**
     * Per-token checks, run after signature, iss, aud and time validation passed
     *
     * @param UnencryptedToken $token
     * @param VerificationOptions $options
     * @param string $audience The audience the token was validated against
     * @return void
     */
    protected function assertOptions(UnencryptedToken $token, VerificationOptions $options, string $audience): void
    {
        $claims = $token->claims();

        if ($options->expectedNonce !== null && !$this->claimEquals($claims->get('nonce'), $options->expectedNonce)) {
            throw new TokenValidationException('Token validation failed: "nonce" claim is missing or does not match');
        }

        if ($options->idToken) {
            // OIDC Core 3.1.3.7: azp is required with multiple audiences and must be our client when present
            if (!$claims->has('azp')) {
                if (count($claims->get(RegisteredClaims::AUDIENCE, [])) > 1) {
                    throw new TokenValidationException('Token validation failed: "azp" claim is required when "aud" has multiple values');
                }
            } elseif (!$this->claimEquals($claims->get('azp'), $audience)) {
                throw new TokenValidationException('Token validation failed: "azp" claim does not match the audience');
            }
        }

        if ($options->requiredScopes !== []) {
            $scopes = $this->scopes($claims->get('scope'));
            if ($scopes === null) {
                throw new TokenValidationException('Token validation failed: "scope" claim is missing or malformed');
            }

            $missing = array_values(array_diff($options->requiredScopes, $scopes));
            if ($missing !== []) {
                throw new TokenValidationException('Token validation failed: missing required scope(s) "' . implode('", "', $missing) . '"');
            }
        }

        if ($options->expectedClientId !== null && !$this->claimEquals($claims->get('client_id'), $options->expectedClientId)) {
            throw new TokenValidationException('Token validation failed: "client_id" claim is missing or does not match');
        }

        if ($options->requireSubject) {
            $subject = $claims->get(RegisteredClaims::SUBJECT);
            if (!is_string($subject) || trim($subject) === '') {
                throw new TokenValidationException('Token validation failed: "sub" claim is missing or blank');
            }
        }

        foreach ($options->claimsEqualIfPresent as $name => $expected) {
            if ($claims->has($name) && !$this->claimEquals($claims->get($name), $expected)) {
                throw new TokenValidationException('Token validation failed: "' . $name . '" claim does not match');
            }
        }
    }

    /**
     * Constant-time comparison of a claim with an expected string
     */
    private function claimEquals(mixed $value, string $expected): bool
    {
        return is_string($value) && hash_equals($expected, $value);
    }

    /**
     * Scopes from a space-delimited string or a list of (space-delimited) strings; null if missing or malformed
     *
     * @param mixed $scope
     * @return list<string>|null
     */
    private function scopes(mixed $scope): ?array
    {
        $items = is_string($scope) ? [$scope] : $scope;

        if (!is_array($items) || $items === [] || !array_is_list($items)) {
            return null;
        }

        $scopes = [];
        foreach ($items as $item) {
            if (!is_string($item) || trim($item) === '') {
                return null;
            }
            array_push($scopes, ...preg_split('/\s+/', trim($item)));
        }

        return $scopes;
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
