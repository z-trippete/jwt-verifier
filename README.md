# JWT Verifier for php

A simple and lightweight php class to verify RS256 JWT tokens using JWKS (JSON Web Key Sets). Perfect for integrating with identity providers (e.g. OpenIddict).

## Features

- **JWKS Support**: Automatically fetches public keys from a remote URL. Keys can be provided either as an `x5c` certificate (preferred when present) or as an RSA modulus/exponent pair (`n`/`e`). Keys whose `use` is set to anything other than `sig` are ignored.
- **Key rotation**: When the token's `kid` is not in the cached JWKS, the JWKS is fetched again once from the provider and the cache is updated, so tokens signed with a newly rotated key are accepted immediately.
- **Smart Caching**: Includes a flexible `CacheManager` to store JWKS data, reducing latency and avoiding rate-limiting from your Identity Provider. The cache key is scoped to the JWKS URL (`oidc_jwks:<sha256 of the URL>`), so several verifiers can share the same cache store.
- **HTTP timeout and injectable client**: The JWKS request has a configurable timeout (10 seconds by default), and you can inject your own Guzzle client.
- **Header validation before any network call**: tokens without a valid `kid` or not signed with `RS256` are rejected without contacting the provider.
- **Claim Validation**: Verifies `iss` (Issuer), `aud` (Audience), `exp` (Expiration), `nbf` (Not Before) and `iat` (Issued At), with an optional clock-skew leeway.
- **Clear Exception Handling**  
  Provides dedicated exceptions for every failure scenario, all extending `JwtVerifierException` (which extends `\Exception`):
  - `TokenFormatException` – Thrown when the JWT structure is invalid or malformed, or the `kid` header is missing, empty or not a string.
  - `TokenValidationException` – Thrown when signature, issuer or audience validation fails, the `alg` header is not `RS256`, `nbf`/`iat` are in the future, or a required time claim is missing.
  - `TokenExpireException` – Thrown when the token is expired (`exp` claim).
  - `OAuthProviderException` – Thrown when the JWKS endpoint cannot be reached, times out, or answers with a non-2xx status.
  - `JwksFormatException` – Thrown when the JWKS response is not valid JSON, has no `keys` array, the requested `kid` is not found (even after a refetch), or the key format is not supported.

## Requirements

- PHP 8.1 or higher
- `ext-openssl`

## Dependencies

This package leverages the most reliable libraries in the PHP ecosystem:
- **[lcobucci/jwt](https://github.com/lcobucci/jwt)**: For high-security JWT parsing and validation (v5.0+).
- **[guzzlehttp/guzzle](https://github.com/guzzle/guzzle)**: For robust HTTP requests to fetch JWKS keys.
- **[psr/clock](https://github.com/php-fig/clock)**: Clock interface used for time-based claims (already required by `lcobucci/jwt`).

## Installation

Install the package via Composer:

```bash
composer require z-trippete/jwt-verifier
```

## Usage

```php
use ZTrippete\JwtVerifier\Verifier;
use ZTrippete\JwtVerifier\Exceptions\JwtVerifierException;

$verifier = new Verifier(
    'https://idp.example.com/.well-known/jwks',
    'https://idp.example.com/',
    'my-api'
);

try {
    $claims = $verifier->verifyAndGetClaims($tokenString);
} catch (JwtVerifierException $e) {
    // Every failure of the library can be caught here,
    // or catch the specific exceptions listed above
}
```

### Constructor options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `jwksUrl` | `string` | — | URL of the provider's JWKS. |
| `issuer` | `string` | — | Expected `iss` claim. |
| `audience` | `?string` | `null` | Expected `aud` claim. When `null`, the token's `sub` claim is used as audience. |
| `cacheManager` | `?CacheManager` | `null` | Cache for the JWKS. Without it, the JWKS is fetched on every verification. |
| `httpClient` | `?GuzzleHttp\ClientInterface` | `null` | Client used to fetch the JWKS. When `null`, a `GuzzleHttp\Client` with `timeout` and `connect_timeout` set to `httpTimeoutSeconds` is created. |
| `httpTimeoutSeconds` | `float` | `10.0` | Timeout of the default HTTP client (ignored when `httpClient` is given: configure your own client). |
| `leewaySeconds` | `int` | `0` | Clock skew tolerated on `exp`, `nbf` and `iat`. |
| `requireTimeClaims` | `bool` | `false` | When `true`, tokens without `exp` or `iat` are rejected with `TokenValidationException`. When `false`, a token **without `exp` is accepted** (it never expires) and a missing `iat` is ignored. |
| `clock` | `?Psr\Clock\ClockInterface` | `null` | Clock used for time-based claims. Defaults to the system clock; inject one for deterministic tests. |

The first four parameters keep their historical order. The new ones are optional: pass them as named arguments.

```php
$verifier = new Verifier(
    jwksUrl: 'https://idp.example.com/.well-known/jwks',
    issuer: 'https://idp.example.com/',
    audience: 'my-api',
    cacheManager: $cacheManager,
    httpTimeoutSeconds: 5.0,
    leewaySeconds: 30,
    requireTimeClaims: true,
);
```

### Time-based claims

With a leeway of `L` seconds:

- `exp <= now - L` → `TokenExpireException`
- `nbf > now + L` → `TokenValidationException`
- `iat > now + L` → `TokenValidationException`

### Caching the JWKS

`CacheManager` takes two closures: one reading a value by key (returning `null` on a miss), one writing it. Example with Laravel:

```php
use Illuminate\Support\Facades\Cache;
use ZTrippete\JwtVerifier\CacheManager;
use ZTrippete\JwtVerifier\Verifier;

$cacheManager = new CacheManager(
    fn(string $key) => Cache::get($key),
    fn(string $key, array $jwks) => Cache::put($key, $jwks, now()->addHours(12))
);

$verifier = new Verifier($jwksUrl, $issuer, $audience, $cacheManager);
```

When the token's `kid` is not in the cached JWKS, the verifier fetches the JWKS once more and stores it through the set closure. If the `kid` is still missing, a `JwksFormatException` is thrown. A JWKS response that is invalid is never cached.

### Custom HTTP client

```php
use GuzzleHttp\Client;

$verifier = new Verifier(
    $jwksUrl,
    $issuer,
    $audience,
    httpClient: new Client(['timeout' => 3, 'proxy' => 'http://proxy.local:3128']),
);
```

## Upgrading to 2.3

- The JWKS cache key changed from `oidc_jwks` to `oidc_jwks:<sha256 of jwksUrl>`: after the upgrade the JWKS is fetched once and stored under the new key. The old entry is no longer read and can be removed.
- Tokens with a `kid` that is missing, empty or not a string now throw `TokenFormatException` (previously a `TypeError`), and tokens whose `alg` is not `RS256` throw `TokenValidationException` before contacting the provider.
- A token with an `iat` or `nbf` in the future is now rejected (use `leewaySeconds` to tolerate clock skew).

## Testing

```bash
composer install
composer test
```

The test suite uses locally generated RSA keys and a mocked HTTP client: it makes no network calls.
