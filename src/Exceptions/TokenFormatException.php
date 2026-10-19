<?php

namespace ZTrippete\JwtVerifier\Exceptions;

use Throwable;

class TokenFormatException extends JwtVerifierException
{
    public function __construct(string $message = "", ?Throwable $previous = null)
    {
        parent::__construct($message, $previous);
    }
}
