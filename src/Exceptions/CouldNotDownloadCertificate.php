<?php

namespace Spatie\SslCertificate\Exceptions;

use Exception;
use Spatie\SslCertificate\Url;

class CouldNotDownloadCertificate extends Exception
{
    public static function hostDoesNotExist(string $hostName): CouldNotDownloadCertificate
    {
        return new static("The host named `{$hostName}` does not exist.");
    }

    public static function noCertificateInstalled(string $hostName): CouldNotDownloadCertificate
    {
        return new static("Could not find a certificate on  host named `{$hostName}`.");
    }

    public static function failedHandshake(Url $url): CouldNotDownloadCertificate
    {
        if ($url->getPort() == "80") {
            return new static("Server does not support SSL over port 80.");
        }
        return new static("Server SSL handshake error – the certificate for `{$url->getTestURL()}` will not work.");
    }

    public static function connectionTimeout(string $hostName): CouldNotDownloadCertificate
    {
        return new static("Connection timed out while testing `{$hostName}`.");
    }

    public static function unknownError(string $hostName, string $errorMessage): CouldNotDownloadCertificate
    {
        return new static("Could not download certificate for host `{$hostName}` because {$errorMessage}");
    }
}
