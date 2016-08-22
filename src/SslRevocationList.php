<?php

namespace Spatie\SslCertificate;

use Carbon\Carbon;

class SslRevocationList
{
    /** @var array */
    protected $rawCertificateRLFields = [];

    public static function createFromUrl(string $url): SslCrl
    {
        $downloadResults = Downloader::downloadRevocationListFromUrl($url);
        dd($downloadResults);

        $rawCertificateRLFields = $downloadResults;

        return new static($rawCertificateRLFields);
    }

    public function __construct(array $rawCertificateRLFields = [])
    {
        $this->rawCertificateRLFields = $rawCertificateRLFields;
    }

    public function parseCrlList(): string
    {
        return;
    }

    public function getCrlList(): string
    {
        $link = $this->getCrlLink();
        $crlList = shell_exec("curl {$link} | openssl crl -inform DER -text -noout");
        //dd( $crlList );
        dd( explode("Revoked Certificates:", $crlList) );

        return $crlList;
    }

}
