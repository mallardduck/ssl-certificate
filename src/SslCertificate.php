<?php

namespace Spatie\SslCertificate;

use Carbon\Carbon;
use phpseclib\Math\BigInteger;
use Spatie\SslCertificate\SslRevocationList;

class SslCertificate
{
    /** @var array */
    protected $rawCertificateFields = [];

    /** @var array */
    protected $rawCertificateChains = [];

    /** @var bool */
    protected $trusted;

    /** @var string */
    protected $ip;

    protected $serial;

    /** @var string */
    protected $crl;

    /** @var string */
    protected $crlLinks = [];

    public static function createForHostName(string $url, int $timeout = 30): SslCertificate
    {
        $downloadResults = Downloader::downloadCertificateFromUrl($url, $timeout);

        $rawCertificateFields = $downloadResults['cert'];
        $rawCertificateChains = $downloadResults['full_chain'];
        $trusted = $downloadResults['trusted'];
        $ip = $downloadResults['resolves-to'];
        $serial = $downloadResults['cert']['serialNumber'];

        return new static($rawCertificateFields, $rawCertificateChains, $trusted, $ip, $serial);
    }

      private function extractCrlLinks($rawCrlPoints)
      {
        $tempCrlItem = explode('URI:',$rawCrlPoints);
        $cleanCrlItem = trim($tempCrlItem[1]);
        return $cleanCrlItem;
      }

    private function setcrlLinks($rawCrlInput)
    {
      $crlLinks = [];
      $crlRawItems = explode('Full Name:',$rawCrlInput);
      // Remove the stuff before the first 'Full Name:' item
      array_splice($crlRawItems, 0, 1);
      foreach ($crlRawItems as $item) {
        $crlLink = self::extractCrlLinks($item);
        array_push($crlLinks, $crlLink);
        unset($crlLink);
      }
      $this->crlLinks = $crlLinks;
    }

    public function __construct(array $rawCertificateFields, array $rawCertificateChains, bool $trusted, string $ip, $serial)
    {
        $this->rawCertificateFields = $rawCertificateFields;
        $this->rawCertificateChains = $rawCertificateChains;
        $this->trusted = $trusted;
        $this->ip = $ip;
        $this->serial = new BigInteger($serial);
        if (isset($rawCertificateFields['extensions']['crlDistributionPoints'])) {
            self::setcrlLinks($rawCertificateFields['extensions']['crlDistributionPoints']);
            $this->crl = SslRevocationList::createFromUrl($this->getCrlLinks()[0]);
        }
    }

    public function getRawCertificateFields(): array
    {
        return $this->rawCertificateFields;
    }

    public function getSerialNumber(): string
    {
        return dec2HexSerial($this->rawCertificateFields['serialNumber']);
    }

    public function hasCrlLink(): bool
    {
        return isset($this->rawCertificateFields['extensions']['crlDistributionPoints']);
    }

    public function getCrlLinks(): array
    {
        if (!$this->hasCrlLink()) {
            return null;
        }
        return $this->crlLinks;
    }

    public function getCrl()
    {
        if (!$this->hasCrlLink()) {
            return null;
        }

        return $this->crl;
    }

    public function isClrRevoked()
    {
        if (!$this->hasCrlLink()) {
            return null;
        }
        foreach ($this->crl->getRevokedList() as $broke){
            if ( $this->serial->equals($broke['userCertificate']) ) {
                return true;
            }
        }
        return false;
    }

    public function getResolvedIp(): string
    {
        return $this->ip;
    }

    public function getIssuer(): string
    {
        return $this->rawCertificateFields['issuer']['CN'];
    }

    public function getDomain(): string
    {
        return $this->rawCertificateFields['subject']['CN'] ?? '';
    }

    public function getSignatureAlgorithm(): string
    {
        return $this->rawCertificateFields['signatureTypeSN'] ?? '';
    }

    public function getAdditionalDomains(): array
    {
        $additionalDomains = explode(', ', $this->rawCertificateFields['extensions']['subjectAltName'] ?? '');

        return array_map(function (string $domain) {
            return str_replace('DNS:', '', $domain);
        }, $additionalDomains);
    }

    public function validFromDate(): Carbon
    {
        return Carbon::createFromTimestampUTC($this->rawCertificateFields['validFrom_time_t']);
    }

    public function expirationDate(): Carbon
    {
        return Carbon::createFromTimestampUTC($this->rawCertificateFields['validTo_time_t']);
    }

    public function isExpired(): bool
    {
        return $this->expirationDate()->isPast();
    }

    public function isTrusted()
    {
        return $this->trusted;
    }

    public function isValid(string $url = null)
    {
        if (! Carbon::now()->between($this->validFromDate(), $this->expirationDate())) {
            return false;
        }

        if (! empty($url)) {
            return $this->appliesToUrl($url ?? $this->getDomain());
        }

        // Check SerialNumber for CRL list

        // Verify SSL is not revoked - OCSP

        return true;
    }

    public function isValidUntil(Carbon $carbon, string $url = null): bool
    {
        if ($this->expirationDate()->gt($carbon)) {
            return false;
        }

        return $this->isValid($url);
    }

    public function appliesToUrl(string $url): bool
    {
        $host = (new Url($url))->getHostName();

        $certificateHosts = array_merge([$this->getDomain()], $this->getAdditionalDomains());

        foreach ($certificateHosts as $certificateHost) {
            if ($host === $certificateHost) {
                return true;
            }

            if ($this->wildcardHostCoversHost($certificateHost, $host)) {
                return true;
            }
        }

        return false;
    }

    protected function wildcardHostCoversHost(string $wildcardHost, string $host): bool
    {
        if ($host === $wildcardHost) {
            return true;
        }

        if (! starts_with($wildcardHost, '*')) {
            return false;
        }

        $wildcardHostWithoutWildcard = substr($wildcardHost, 2);

        return ends_with($host, $wildcardHostWithoutWildcard);
    }
}
