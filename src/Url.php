<?php

namespace Spatie\SslCertificate;

use Spatie\SslCertificate\Exceptions\InvalidUrl;

class Url
{
    /** @var string */
    protected $url;

    /** @var array */
    protected $parsedUrl;

    /** @var int */
    protected $ipAddress;

    public static function verifyDNS($domain): string
    {
        $domainIp = gethostbyname($domain);
        if (!filter_var($domainIp, FILTER_VALIDATE_IP)) {
            throw InvalidUrl::couldNotResolveDns($domain);
        }
        return $domainIp;
    }

    public function __construct(string $url)
    {
        if (! starts_with($url, ['http://', 'https://'])) {
            $url = "https://{$url}";
        }

        if (! filter_var($url, FILTER_VALIDATE_URL)) {
            throw InvalidUrl::couldNotValidate($url);
        }

        $this->url = $url;

        $this->parsedUrl = parse_url($url);

        if (! isset($this->parsedUrl['host'])) {
            throw InvalidUrl::couldNotDetermineHost($this->url);
        }

        $this->ipAddress = $this->verifyDNS($this->parsedUrl['host']);

    }

    public function getHostName(): string
    {
        return $this->parsedUrl['host'];
    }

    public function getPort(): string
    {
        return (isset($this->parsedUrl['port'])) ? $this->parsedUrl['port'] : '443';
    }

    public function getIp(): string
    {
        return $this->ipAddress;
    }

}
