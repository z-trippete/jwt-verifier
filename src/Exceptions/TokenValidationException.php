<?php

namespace ZTrippete\JwtVerifier\Exceptions;

use Throwable;

class TokenValidationException extends JwtVerifierException
{
    public function __construct(string $message = "", ?Throwable $previous = null)
    {
        parent::__construct($message, $previous);
    }
}
