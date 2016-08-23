<?php

namespace Spatie\SslCertificate;

use Carbon\Carbon;
use Spatie\SslCertificate\IssuerMeta;

class SslRevocationList
{
    /** @var Carbon */
    protected $timestamp;

    /** @var array */
    protected $issuer;

    /** @var Carbon */
    protected $createdAt;

    /** @var Carbon */
    protected $expiration;

    /** @var Carbon */
    protected $ttl;

    /** @var string */
    protected $signature = [];

    /** @var array */
    protected $signatureAlgorithm = [];

    /** @var array */
    protected $revokedCertsList = [];

    public static function createFromUrl(string $url): SslRevocationList
    {
        $downloadResults = Downloader::downloadRevocationListFromUrl($url);
        $tbsCertList = $downloadResults['tbsCertList'];
        $issuer = IssuerMeta::fromRdnSequence($downloadResults['tbsCertList']['issuer']['rdnSequence']);
        $createdAt = $downloadResults['tbsCertList']['thisUpdate']['utcTime'];
        $expiration = $downloadResults['tbsCertList']['nextUpdate']['utcTime'];
        $signature = $downloadResults['signature'];
        $signatureAlgorithm = $downloadResults['signatureAlgorithm'];
        $certsList = $downloadResults['tbsCertList']['revokedCertificates'];

        return new static($issuer, $createdAt, $expiration, $signature, $signatureAlgorithm, $certsList);
    }

    public function __construct(IssuerMeta $issuer = null, string $createdAt = "", string $expiration = "", string $signature = "", array $signatureAlgorithm = [], array $certsList = [])
    {
        $this->timestamp = Carbon::now();
        $this->issuer = $issuer;
        $this->createdAt = Carbon::parse($createdAt)->setTimezone('UTC');
        $this->expiration = Carbon::parse($expiration)->setTimezone('UTC');
        $this->ttl = Carbon::parse($expiration)->diffInMinutes(Carbon::now());
        $this->signature = $signature;
        $this->signatureAlgorithm = $signatureAlgorithm;
        $this->revokedCertsList = $certsList;
    }

    public function getRevokedList(): array
    {
        return $this->revokedCertsList;
    }
}
