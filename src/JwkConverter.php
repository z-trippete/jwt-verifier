<?php

namespace ZTrippete\JwtVerifier;

use ZTrippete\JwtVerifier\Exceptions\JwksFormatException;

/**
 * Converts an RSA JWK into a PEM string usable by lcobucci/jwt.
 *
 * The `x5c` certificate is preferred when present; otherwise the public key
 * is rebuilt from the modulus (`n`) and exponent (`e`) as a DER SubjectPublicKeyInfo.
 *
 * @internal
 */
final class JwkConverter
{
    // DER encoding of: SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }
    private const RSA_ALGORITHM_IDENTIFIER = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

    /**
     * @param array $jwk
     * @return string
     * @throws JwksFormatException
     */
    public static function toPem(array $jwk): string
    {
        if (isset($jwk['x5c'][0]) && is_string($jwk['x5c'][0])) {
            $pem = "-----BEGIN CERTIFICATE-----\n" .
                chunk_split($jwk['x5c'][0], 64, "\n") .
                "-----END CERTIFICATE-----\n";
        } elseif (
            ($jwk['kty'] ?? null) === 'RSA'
            && isset($jwk['n'], $jwk['e'])
            && is_string($jwk['n'])
            && is_string($jwk['e'])
        ) {
            $pem = self::rsaPublicKeyPem($jwk['n'], $jwk['e']);
        } else {
            throw new JwksFormatException('Not supported JWKS format key');
        }

        self::assertRsaPublicKey($pem);

        return $pem;
    }

    private static function rsaPublicKeyPem(string $n, string $e): string
    {
        $modulus = self::base64UrlDecode($n);
        $exponent = self::base64UrlDecode($e);

        if ($modulus === null || $exponent === null) {
            throw new JwksFormatException('Invalid RSA modulus or exponent in JWKS key');
        }

        $rsaPublicKey = self::tlv("\x30", self::integer($modulus) . self::integer($exponent));
        $subjectPublicKeyInfo = self::tlv(
            "\x30",
            self::RSA_ALGORITHM_IDENTIFIER . self::tlv("\x03", "\x00" . $rsaPublicKey)
        );

        return "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n") .
            "-----END PUBLIC KEY-----\n";
    }

    private static function assertRsaPublicKey(string $pem): void
    {
        $key = openssl_pkey_get_public($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);

        // Drain the OpenSSL error queue so failures don't leak into later openssl_* calls
        while (openssl_error_string() !== false);

        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new JwksFormatException('Invalid RSA public key in JWKS');
        }
    }

    /**
     * Unsigned big-endian bytes to a DER INTEGER
     */
    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '' || ord($bytes[0]) > 0x7f) {
            $bytes = "\x00" . $bytes;
        }

        return self::tlv("\x02", $bytes);
    }

    private static function tlv(string $tag, string $value): string
    {
        $length = strlen($value);

        if ($length < 0x80) {
            return $tag . chr($length) . $value;
        }

        $lengthBytes = ltrim(pack('N', $length), "\x00");

        return $tag . chr(0x80 | strlen($lengthBytes)) . $lengthBytes . $value;
    }

    private static function base64UrlDecode(string $value): ?string
    {
        if ($value === '' || !preg_match('/^[A-Za-z0-9_-]+={0,2}$/', $value)) {
            return null;
        }

        $decoded = base64_decode(strtr(rtrim($value, '='), '-_', '+/'), true);

        return $decoded === false || $decoded === '' ? null : $decoded;
    }
}
