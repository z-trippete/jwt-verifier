<?php

namespace ZTrippete\JwtVerifier\Exceptions;

use Exception;

class TokenValidationException extends Exception
{
    public function __construct(string $message = "")
    {
        parent::__construct($message);
    }
}
