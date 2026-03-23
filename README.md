# JWT Verifier for php

A simple and lightweight php class to verify JWT tokens using JWKS (JSON Web Key Sets). Perfect for integrating with identity providers.

## Features

- **JWKS Support**: Automatically fetches public keys from a remote URL.
- **Smart Caching**: Includes a flexible `CacheManager` to store JWKS data, reducing latency and avoiding rate-limiting from your Identity Provider.
- **Claim Validation**: Verifies `iss` (Issuer), `aud` (Audience), and `exp` (Expiration).
- **Clear Exception Handling**  
  Provides dedicated exceptions for every failure scenario:
  - `TokenFormatException` – Thrown when the JWT structure is invalid or malformed.
  - `TokenValidationException` – Thrown when signature, issuer, or audience validation fails.
  - `TokenExpireException` – Thrown when the token is expired (`exp` claim).
  - `OAuthProviderException` – Thrown when the JWKS endpoint cannot be reached or the HTTP request fails.
  - `JwksFormatException` – Thrown when the JWKS response is malformed, missing keys, or the requested `kid` is not found.

## Requirements

- PHP 8.1 or higher

## Dependencies

This package leverages the most reliable libraries in the PHP ecosystem:
- **[lcobucci/jwt](https://github.com/lcobucci/jwt)**: For high-security JWT parsing and validation (v5.0+).
- **[guzzlehttp/guzzle](https://github.com/guzzle/guzzle)**: For robust asynchronous HTTP requests to fetch JWKS keys.

## Installation

Install the package via Composer:

```bash
composer require z-trippete/jwt-verifier