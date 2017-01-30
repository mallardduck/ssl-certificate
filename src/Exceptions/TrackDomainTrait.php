<?php

namespace LiquidWeb\SslCertificate\Exceptions;

trait TrackDomainTrait
{
    protected $errorDomain;

    private function setErrorDomain(string $domain)
    {
        $this->errorDomain = $domain;
    }

    private function getErrorDomain(string $domain)
    {
        return $this->errorDomain;
    }
}
