<?php

namespace ZTrippete\JwtVerifier\Exceptions;

use Exception;
use Throwable;

/**
 * Base class for every exception thrown by the library,
 * so consumers can catch all verification failures with a single catch block.
 */
class JwtVerifierException extends Exception
{
    public function __construct(string $message = "", ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
