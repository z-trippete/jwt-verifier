# Changelog

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
