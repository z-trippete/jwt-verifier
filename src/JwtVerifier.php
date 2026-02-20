<?php

namespace ZTrippete\JwtVerifier;

use Closure;
use DateTimeImmutable;
use Exception;
use GuzzleHttp\Client;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

class JwtVerifier
{
    /**
     * This function validate token and return all claims
     *
     * @param JwtVerifierDTO $jwtVerifierDTO
     * @return array
     */
    public function validateJwtAndGetClaims(JwtVerifierDTO $jwtVerifierDTO): array
    {
        if (!$jwtVerifierDTO->tokenString) {
            throw new Exception('Token not provided', 401);
        }

        try {
            // Parse the token header to retrieve the KID (Key ID)
            $parser = new Parser(new JoseEncoder());
            $parsedToken = $parser->parse($jwtVerifierDTO->tokenString);

            $kid = $parsedToken->headers()->get('kid');

            $publicKey = $this->getPublicKeyFromJwks(
                $jwtVerifierDTO->config['urlKey'],
                $kid,
                $jwtVerifierDTO->cacheSet,
                $jwtVerifierDTO->cacheGet,
                $jwtVerifierDTO->cacheKey
            );

            // Creare la configurazione principale
            $configuration = Configuration::forAsymmetricSigner(
                new Sha256(),
                $publicKey, // Expects a key even though we are not interested in it
                $publicKey
            );

            /** @var Plain */
            $token = $configuration->parser()->parse($jwtVerifierDTO->tokenString);

            $constraints = [
                // Verify that the token was issued by the configured OIDC server
                new IssuedBy($jwtVerifierDTO->config['issuer']),
                // Verify that the token was signed by the configured OIDC server
                new SignedWith($configuration->signer(), $configuration->verificationKey()),
                // Verify that the token was issued for this application
                new PermittedFor($jwtVerifierDTO->config['audience'])
            ];

            // Validate the token against all constraints
            foreach ($constraints as $constraint) {
                $configuration->validator()->assert($token, $constraint);
            }

            // If all validations pass, the token is valid
            $claims = $token->claims()->all();

            $now = new DateTimeImmutable();

            // Check that the token has not expired
            if ($claims['exp'] <= $now) {
                throw new Exception('Token expired', 401);
            }

            return $claims;
        } catch (\Throwable $th) {
            throw new Exception($th->getMessage(), 401);
        }
    }

    /**
     * Function that fetches the public key from a URL and returns the key in PEM format.
     *
     * @param string $jwksUrl
     * @param string $kid
     * @param Closure|null $cacheSet
     * @param Closure|null $cacheGet
     * @param string|null $cacheKey
     * @return Key
     */
    protected function getPublicKeyFromJwks(string $jwksUrl, string $kid, ?Closure $cacheSet, ?Closure $cacheGet, ?string $cacheKey): Key
    {
        $jwksData = null;

        if ($cacheGet && $cacheKey) {
            $jwksData = $cacheGet($cacheKey);
        }

        if (!$jwksData) {
            $client = new Client();
            $response = $client->get($jwksUrl);
            $jwksData = json_decode($response->getBody()->getContents(), true);

            if ($cacheSet && $cacheKey && $jwksData) {
                $cacheSet($cacheKey, $jwksData);
            }
        }

        if (!isset($jwksData['keys']) || !is_array($jwksData['keys'])) {
            throw new Exception('JWKS not valid or without key');
        }

        $targetKey = null;
        foreach ($jwksData['keys'] as $key) {
            if (isset($key['kid']) && $key['kid'] === $kid) {
                $targetKey = $key;
                break;
            }
        }

        if (!$targetKey) {
            throw new Exception('Public Key not found in JWKS for KID');
        }

        if (!isset($targetKey['x5c'][0])) {
            throw new Exception('Not supported JWKS format key');
        }

        return InMemory::plainText(
            "-----BEGIN CERTIFICATE-----\n" .
                chunk_split($targetKey['x5c'][0], 64, "\n") .
                "-----END CERTIFICATE-----\n"
        );
    }
}
