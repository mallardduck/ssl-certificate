<?php

namespace LiquidWeb\SslCertificate\Exceptions;

trait TrackDomainTrait
{
    protected $errorDomain;

    private function setErrorDomain(string $domain)
    {
        $this->errorDomain = $domain;
    }

    public function getErrorDomain()
    {
        return $this->errorDomain;
    }
}
