<?php

namespace ZTrippete\JwtVerifier;

use InvalidArgumentException;

/**
 * Optional per-token checks for Verifier::verifyAndGetClaims().
 * Every failed check throws TokenValidationException.
 *
 * @param string|null $expectedType = null Expected "typ" header (e.g. "at+jwt"), case-insensitive, "application/" prefix optional
 * @param string|null $expectedNonce = null Expected "nonce" claim (ID tokens)
 * @param bool $idToken = false Apply the OIDC "azp" rules (OIDC Core 3.1.3.7)
 * @param list<string> $requiredScopes = [] Scopes that must all be present in the "scope" claim
 * @param string|null $expectedClientId = null Expected "client_id" claim (RFC 9068)
 * @param bool $requireSubject = false Require a non-blank "sub" claim
 * @param array<string, string> $claimsEqualIfPresent = [] Claims that, when present, must be equal to the given value
 */
final class VerificationOptions
{
    public function __construct(
        public readonly ?string $expectedType = null,
        public readonly ?string $expectedNonce = null,
        public readonly bool $idToken = false,
        public readonly array $requiredScopes = [],
        public readonly ?string $expectedClientId = null,
        public readonly bool $requireSubject = false,
        public readonly array $claimsEqualIfPresent = []
    ) {
        foreach (['expectedType' => $expectedType, 'expectedNonce' => $expectedNonce, 'expectedClientId' => $expectedClientId] as $name => $value) {
            if ($value !== null && trim($value) === '') {
                throw new InvalidArgumentException("\$$name must not be blank");
            }
        }

        foreach ($requiredScopes as $scope) {
            if (!is_string($scope) || !preg_match('/^\S+$/', $scope)) {
                throw new InvalidArgumentException('$requiredScopes must be a list of non-blank strings without spaces');
            }
        }

        foreach ($claimsEqualIfPresent as $claim => $value) {
            if (!is_string($claim) || $claim === '' || !is_string($value)) {
                throw new InvalidArgumentException('$claimsEqualIfPresent must map claim names to string values');
            }
        }
    }
}
