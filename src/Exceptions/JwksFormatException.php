<?php

namespace ZTrippete\JwtVerifier\Exceptions;

use Throwable;

class JwksFormatException extends JwtVerifierException
{
    public function __construct(string $message = "", ?Throwable $previous = null)
    {
        parent::__construct($message, $previous);
    }
}
