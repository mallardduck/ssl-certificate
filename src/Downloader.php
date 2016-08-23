<?php

namespace Spatie\SslCertificate;

use Spatie\SslCertificate\Exceptions\CouldNotDownloadCertificate;
use Spatie\SslCertificate\StreamConfig;
use phpseclib\File\X509;
use Throwable;

class Downloader
{

    /** @var string */
    protected $inputUrl;

    /** @var array */
    protected $results;

    public static function downloadCertificateFromUrl(string $url, int $timeout = 30): array
    {
        // Trusted variable to keep track of SSL trust
        $trusted = true;
        $sslConfig = StreamConfig::configSecure($timeout);
        $parsedUrl = new Url($url);
        $hostName = $parsedUrl->getHostName();
        $testUrl = "{$parsedUrl->getHostName()}:{$parsedUrl->getPort()}";

        try {
            $client = stream_socket_client(
                "ssl://{$testUrl}",
                $errorNumber,
                $errorDescription,
                $timeout,
                STREAM_CLIENT_CONNECT,
                $sslConfig->getContext()
            );
            unset($sslConfig);
        } catch (Throwable $thrown) {
            // Unset previous vars just to keep things legit
            unset($client);
            // Try agian in insecure mode
            $sslConfig = StreamConfig::configInsecure($timeout);

            try {
                // As the URL failed varification we set to false
                $trusted = false;
                $client = stream_socket_client(
                    "ssl://{$testUrl}",
                    $errorNumber,
                    $errorDescription,
                    $timeout,
                    STREAM_CLIENT_CONNECT,
                    $sslConfig->getContext()
                );
                unset($sslConfig);
                $domainIp = gethostbyname( $hostName );

                return self::prepareCertificateResponse($client, $trusted, $domainIp, $testUrl);
            } catch (Throwable $thrown) {
                if (str_contains($thrown->getMessage(), 'getaddrinfo failed')) {
                    throw CouldNotDownloadCertificate::hostDoesNotExist($hostName);
                }

                if (str_contains($thrown->getMessage(), 'error:14090086')) {
                    throw CouldNotDownloadCertificate::noCertificateInstalled($hostName);
                }

                if (str_contains($thrown->getMessage(), 'error:14077410') || str_contains($thrown->getMessage(), 'error:140770FC')) {
                    throw CouldNotDownloadCertificate::failedHandshake($parsedUrl);
                }

                if (str_contains($thrown->getMessage(), '(Connection timed out)')) {
                    throw CouldNotDownloadCertificate::connectionTimeout($testUrl);
                }

                throw CouldNotDownloadCertificate::unknownError($testUrl, $thrown->getMessage());
            }
        }
        $domainIp = gethostbyname( $hostName );

        return self::prepareCertificateResponse($client, $trusted, $domainIp, $testUrl);
    }

    private static function prepareCertificateResponse($client, bool $trusted, string $domainIp, string $testUrl): array
    {
        $results = [
            'tested' => $testUrl,
            'trusted' => $trusted,
            'dns-resolves-to' => $domainIp,
            'cert' => null,
            'full_chain' => [],
            'connection' => [],
        ];
        $response = stream_context_get_options($client);
        $results['connection'] = stream_get_meta_data($client)['crypto'];
        unset($client);
        $results['cert'] = openssl_x509_parse($response['ssl']['peer_certificate']);

        if (count($response["ssl"]["peer_certificate_chain"]) > 1) {
            foreach($response["ssl"]["peer_certificate_chain"] as $cert)
            {
                $parsedCert = openssl_x509_parse($cert);
                $isChain = ($parsedCert['hash'] !== $results['cert']['hash']);
                if ($isChain) {
                    array_push($results['full_chain'],$parsedCert);
                }
            }
        }

        return $results;
    }

    public static function downloadRevocationListFromUrl(string $url): array
    {
        $parsedUrl = new Url($url);
        $csrConfig = StreamConfig::configCrl();
        $file = file_get_contents($parsedUrl->getValidatedURL(), false, $csrConfig->getContext());
        unset($csrConfig, $parsedUrl);
        $x509 = new X509();
        $crl = $x509->loadCRL($file); // see ev2009a.crl
        unset($x509, $file);

        return $crl;
    }

}
