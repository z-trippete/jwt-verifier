# Changelog

## 2.4.0

### Added
- `VerificationOptions`: per-token checks passed as the optional second argument, `verifyAndGetClaims(string $tokenString, ?VerificationOptions $options = null)`. Every failed check throws `TokenValidationException`.
  - `expectedType`: `typ` header check (RFC 9068 / RFC 7515). It is case-insensitive, accepts an optional `application/` prefix, and runs before any JWKS fetch.
  - `expectedNonce` and `idToken`: OIDC ID token `nonce` and `azp` rules (OIDC Core 3.1.3.7).
  - `requiredScopes`: `scope` given as a space-delimited string or as a list of strings, matched on whole tokens.
  - `expectedClientId` (`client_id`, RFC 9068), `requireSubject` (non-blank `sub`) and `claimsEqualIfPresent` (e.g. OpenIddict `oi_prst`).
  - These checks run only after signature, `iss`, `aud` and time validation, and compare claim values with `hash_equals`.
- `rawTimeClaims` constructor option (trailing, default `false`): returns `exp`, `iat` and `nbf` as integer Unix timestamps.

### Changed
- Hardening: a token whose `aud` contains a non-string value is now rejected with `TokenValidationException`. This affects malformed tokens only.
- Subclasses overriding `verifyAndGetClaims()` must add the new optional `$options` parameter to their signature.

## 2.3.0

### Added
- Key rotation: when the token's `kid` is not found in the cached JWKS, the JWKS is fetched again once and stored through the `CacheManager`.
- Support for RSA JWKs without `x5c`, built from the modulus (`n`) and exponent (`e`). `x5c` remains preferred when present.
- Keys whose `use` is set to anything other than `sig` are ignored.
- Optional constructor parameters (trailing, with defaults): `httpClient`, `httpTimeoutSeconds` (10 s), `leewaySeconds` (0), `requireTimeClaims` (false), `clock` (`Psr\Clock\ClockInterface`).
- `nbf` and `iat` validation, with clock-skew leeway applied to `exp`, `nbf` and `iat`.
- `JwtVerifierException`: common base class of all the library exceptions (which still extend `\Exception`). Exceptions now accept an optional `$previous`.
- `CacheManager::refresh()`.
- PHPUnit test suite.

### Changed
- The JWKS cache key is now scoped to the JWKS URL: `oidc_jwks:<sha256 of jwksUrl>` (was `oidc_jwks`).
- The `kid` and `alg` headers are validated before any JWKS fetch: an invalid `kid` throws `TokenFormatException` (was a `TypeError`), an `alg` other than `RS256` throws `TokenValidationException`.
- JWKS HTTP errors (non-2xx status, transport error, timeout) throw `OAuthProviderException`; a body that is not valid JSON or has no `keys` array throws `JwksFormatException` and is not cached.
- Any token parsing error throws `TokenFormatException`.
- A missing `exp` no longer raises a PHP warning: it is accepted unless `requireTimeClaims` is `true`.
- When no audience is configured and the token has no `sub`, `TokenValidationException` is thrown (was a `TypeError`).
