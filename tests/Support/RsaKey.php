<?php

namespace ZTrippete\JwtVerifier\Tests\Support;

use RuntimeException;

/**
 * Locally generated RSA key pair (plus self-signed certificate) used to sign test tokens
 */
final class RsaKey
{
    private static array $cache = [];

    private function __construct(
        public readonly string $privatePem,
        public readonly string $publicPem,
        public readonly string $modulus,
        public readonly string $exponent,
        public readonly string $certificateDerBase64
    ) {}

    public static function get(string $name): self
    {
        return self::$cache[$name] ??= self::generate();
    }

    private static function generate(): self
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($key === false || !openssl_pkey_export($key, $privatePem)) {
            throw new RuntimeException('Unable to generate RSA key: ' . openssl_error_string());
        }

        $details = openssl_pkey_get_details($key);

        $csr = openssl_csr_new(['commonName' => 'jwt-verifier-tests'], $key, ['digest_alg' => 'sha256']);
        $certificate = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
        openssl_x509_export($certificate, $certificatePem);
        $certificateDerBase64 = preg_replace('/-----[^-]+-----|\s/', '', $certificatePem);

        while (openssl_error_string() !== false);

        return new self(
            $privatePem,
            $details['key'],
            $details['rsa']['n'],
            $details['rsa']['e'],
            $certificateDerBase64
        );
    }

    public function x5cJwk(string $kid, array $extra = []): array
    {
        return $extra + ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'x5c' => [$this->certificateDerBase64]];
    }

    public function modulusExponentJwk(string $kid, array $extra = []): array
    {
        return $extra + [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => self::base64Url($this->modulus),
            'e' => self::base64Url($this->exponent),
        ];
    }

    public static function base64Url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
