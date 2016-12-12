<?php

namespace LiquidWeb\SslCertificate;

use League\Uri\UriParser;
use LiquidWeb\SslCertificate\Exceptions\InvalidUrl;

class Url
{
    /** @var string */
    protected $inputUrl;

    /** @var array */
    protected $parsedUrl;

    /** @var string */
    protected $validatedURL;

    /** @var string */
    protected $ipAddress;

    private static function verifyAndGetDNS($domain): string
    {
        $domainIp = gethostbyname($domain);
        if (!filter_var($domainIp, FILTER_VALIDATE_IP)) {
            throw InvalidUrl::couldNotResolveDns($domain);
        }
        return $domainIp;
    }

    private static function isValidFqdn($domain): bool
    {
        if (!filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
            return false;
        }
        return true;
    }

    private static function isValidUrl($domain): bool
    {
        if (!filter_var($domain, FILTER_VALIDATE_URL)) {
            return false;
        }
        return true;
    }

    public function __construct(string $url)
    {
        $this->inputUrl = $url;
        $parser = new UriParser();
        $this->parsedUrl = $parser->parse($this->inputUrl);

        // Verify parsing has a host
        if (is_null($this->parsedUrl['host'])) {
            $this->parsedUrl = $parser->parse('https://'.$this->inputUrl);
            if (is_null($this->parsedUrl['host'])) {
                throw InvalidUrl::couldNotDetermineHost($url);
            }
        }

        if (! filter_var((string) $this->getValidUrl(), FILTER_VALIDATE_URL)) {
            throw InvalidUrl::couldNotValidate($url);
        }

        $this->ipAddress = self::verifyAndGetDNS($this->parsedUrl['host']);
        $this->validatedURL = $url;
    }

    public function getIp(): string
    {
        return $this->ipAddress;
    }

    public function getHostName(): string
    {
        return $this->parsedUrl['host'];
    }

    public function getValidatedURL(): string
    {
        return $this->validatedURL;
    }

    public function getPort(): string
    {
        return (isset($this->parsedUrl['port'])) ? $this->parsedUrl['port'] : '443';
    }

    public function getTestURL(): string
    {
        return "{$this->getHostName()}:{$this->getPort()}";
    }

    public function getValidUrl(): string
    {
        if ($this->getPort() === '80') {
            return 'http://'.$this->getHostName().'/';
        }
        return 'https://'.$this->getHostName().'/';
    }
}
