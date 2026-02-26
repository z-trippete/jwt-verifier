<?php

namespace ZTrippete\JwtVerifier\Exceptions;

use Exception;

class TokenFormatException extends Exception
{
    public function __construct(string $message = "")
    {
        parent::__construct($message);
    }
}
