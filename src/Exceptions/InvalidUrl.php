<?php

namespace LiquidWeb\SslCertificate\Exceptions;

use Exception;

class InvalidUrl extends Exception
{
    public static function couldNotValidate(string $url): InvalidUrl
    {
        return new static("String `{$url}` is not a valid url.");
    }

    public static function couldNotDetermineHost(string $url): InvalidUrl
    {
        return new static("Could not determine host from url `{$url}`.");
    }

    public static function couldNotResolveDns(string $hostName): InvalidUrl
    {
        return new static("The domain `{$hostName}` does not have a valid DNS record.");
    }
}
