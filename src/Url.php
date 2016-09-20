<?php

namespace LiquidWeb\SslCertificate;

use LiquidWeb\SslCertificate\Exceptions\InvalidUrl;

class Url
{

    /** @var string */
    protected $inputUrl;

    /** @var array */
    protected $parsedUrl;

    /** @var string */
    protected $validatedURL;

    /** @var int */
    protected $ipAddress;

    private static function verifyDNS($domain): string
    {
        $domainIp = gethostbyname($domain);
        if (!filter_var($domainIp, FILTER_VALIDATE_IP)) {
            throw InvalidUrl::couldNotResolveDns($domain);
        }
        return $domainIp;
    }

    public function __construct(string $url)
    {
        $this->inputUrl = $url;
        if (! starts_with($url, ['http://', 'https://'])) {
            $url = "https://{$url}";
        }

        if (! filter_var($url, FILTER_VALIDATE_URL)) {
            throw InvalidUrl::couldNotValidate($url);
        }

        $this->parsedUrl = parse_url($url);

        if (! isset($this->parsedUrl['host'])) {
            throw InvalidUrl::couldNotDetermineHost($url);
        }

        $this->ipAddress = self::verifyDNS($this->parsedUrl['host']);
        $this->validatedURL = $url;
    }

    public function getValidatedURL(): string
    {
        return $this->validatedURL;
    }

    public function getHostName(): string
    {
        return $this->parsedUrl['host'];
    }

    public function getPort(): string
    {
        return (isset($this->parsedUrl['port'])) ? $this->parsedUrl['port'] : '443';
    }

    public function getTestURL(): string
    {
        return "{$this->getHostName()}:{$this->getPort()}";
    }

    public function getIp(): string
    {
        return $this->ipAddress;
    }
}
