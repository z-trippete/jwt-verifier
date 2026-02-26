<?php

namespace ZTrippete\JwtVerifier;

use DateTimeImmutable;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use ZTrippete\JwtVerifier\Exceptions\JwksFormatException;
use ZTrippete\JwtVerifier\Exceptions\OAuthProviderException;
use ZTrippete\JwtVerifier\Exceptions\TokenExpireException;
use ZTrippete\JwtVerifier\Exceptions\TokenFormatException;
use ZTrippete\JwtVerifier\Exceptions\TokenValidationException;

/**
 * @param string $jwksUrl
 * @param string $issuer
 * @param string $audience
 * @param CacheManager|null $cacheManager = null
 */
class Verifier
{
    public function __construct(
        readonly string $jwksUrl,
        readonly string $issuer,
        readonly string $audience,
        readonly ?CacheManager $cacheManager = null
    ) {}

    /**
     * This function validate token and return all claims
     *
     * @param string $tokenString
     * @return array
     */
    public function verifyAndGetClaims(string $tokenString): array
    {
        // Parse the token header to retrieve the KID (Key ID)
        $parser = new Parser(new JoseEncoder());
        try {
            $parsedToken = $parser->parse($tokenString);
        } catch (InvalidTokenStructure | UnsupportedHeaderFound $e) {
            throw new TokenFormatException('Invalid token format: ' . $e->getMessage());
        }

        $publicKey = $this->getPublicKeyFromJwks($parsedToken->headers()->get('kid'));

        // Create the main configuration
        $configuration = Configuration::forAsymmetricSigner(
            new Sha256(),
            $publicKey, // Expects a key even though we are not interested in it
            $publicKey
        );

        /** @var Plain */
        $token = $configuration->parser()->parse($tokenString);

        $constraints = [
            // Verify that the token was issued by the configured OIDC server
            new IssuedBy($this->issuer),
            // Verify that the token was signed by the configured OIDC server
            new SignedWith($configuration->signer(), $configuration->verificationKey()),
            // Verify that the token was issued for this application
            new PermittedFor($this->audience)
        ];

        // Validate the token against all constraints
        try {
            foreach ($constraints as $constraint) {
                $configuration->validator()->assert($token, $constraint);
            }
        } catch (RequiredConstraintsViolated $e) {
            throw new TokenValidationException('Token validation failed: ' . $e->getMessage());
        }

        // If all validations pass, the token is valid
        $claims = $token->claims()->all();

        $now = new DateTimeImmutable();

        // Check that the token has not expired
        if ($claims['exp'] <= $now) {
            throw new TokenExpireException('Token expired');
        }

        return $claims;
    }

    /**
     * Function that fetches the public key from a URL and returns the key in PEM format.
     *
     * @param string $jwksUrl
     * @param string $kid
     * @param CacheManager|null $cacheManager
     * @return Key
     */
    protected function getPublicKeyFromJwks(string $kid): Key
    {
        $fetchJwksData = function (): array {
            try {
                $client = new Client();
                $response = $client->get($this->jwksUrl);
                return json_decode($response->getBody()->getContents(), true);
            } catch (GuzzleException $e) {
                throw new OAuthProviderException('Error during fetch JWKS from provider:' . $e->getMessage());
            }
        };

        $jwksData = $this->cacheManager ? $this->cacheManager->remember('oidc_jwks', $fetchJwksData) : $fetchJwksData();

        if (!isset($jwksData['keys']) || !is_array($jwksData['keys'])) {
            throw new JwksFormatException('JWKS not valid or without key');
        }

        $targetKey = null;
        foreach ($jwksData['keys'] as $key) {
            if (isset($key['kid']) && $key['kid'] === $kid) {
                $targetKey = $key;
                break;
            }
        }

        if (!$targetKey) {
            throw new JwksFormatException('Public Key not found in JWKS for KID');
        }

        if (!isset($targetKey['x5c'][0])) {
            throw new JwksFormatException('Not supported JWKS format key');
        }

        return InMemory::plainText(
            "-----BEGIN CERTIFICATE-----\n" .
                chunk_split($targetKey['x5c'][0], 64, "\n") .
                "-----END CERTIFICATE-----\n"
        );
    }
}
