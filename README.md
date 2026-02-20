# JWT Verifier for php

A simple and lightweight php class to verify JWT tokens using JWKS (JSON Web Key Sets). Perfect for integrating with identity providers.

## Features

- **JWKS Support**: Automatically fetches public keys from a remote URL.
- **Claim Validation**: Verifies `iss` (Issuer), `aud` (Audience), and `exp` (Expiration).

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