<?php

namespace LiquidWeb\SslCertificate;

use LiquidWeb\SslCertificate\Exceptions\CouldNotDownloadCertificate;
use LiquidWeb\SslCertificate\StreamConfig;
use phpseclib\File\X509;
use Throwable;

class Downloader
{

    public static function downloadCertificateFromUrl(string $url, int $timeout = 30): array
    {
        // Trusted variable to keep track of SSL trust
        $trusted = true;
        $sslConfig = StreamConfig::configSecure();
        $parsedUrl = new Url($url);
        $hostName = $parsedUrl->getHostName();
        $client = null;

        try {
            $client = stream_socket_client(
                "ssl://{$parsedUrl->getTestURL()}",
                $errorNumber,
                $errorDescription,
                $timeout,
                STREAM_CLIENT_CONNECT,
                $sslConfig->getContext()
            );
            unset($sslConfig);
        } catch (Throwable $thrown) {
            // Try agian in insecure mode
            $sslConfig = StreamConfig::configInsecure();

            try {
                // As the URL failed verification we set to false
                $trusted = false;
                $client = stream_socket_client(
                    "ssl://{$parsedUrl->getTestURL()}",
                    $errorNumber,
                    $errorDescription,
                    $timeout,
                    STREAM_CLIENT_CONNECT,
                    $sslConfig->getContext()
                );
                unset($sslConfig);

                return self::prepareCertificateResponse($client, $trusted, $parsedUrl->getIp(), $parsedUrl->getTestURL());
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
                    throw CouldNotDownloadCertificate::connectionTimeout($parsedUrl->getTestURL());
                }

                throw CouldNotDownloadCertificate::unknownError($parsedUrl->getTestURL(), $thrown->getMessage());
            }
        }

        $sslData = self::prepareCertificateResponse($client, $trusted, $parsedUrl->getIp(), $parsedUrl->getTestURL());
        return $sslData;
    }

    private static function prepareCertificateResponse($resultClient, bool $trusted, string $domainIp, string $testedUrl): array
    {
        $results = [
            'tested' => $testedUrl,
            'trusted' => $trusted,
            'dns-resolves-to' => $domainIp,
            'cert' => null,
            'full_chain' => [],
            'connection' => [],
        ];
        $response = stream_context_get_options($resultClient);
        $results['connection'] = stream_get_meta_data($resultClient)['crypto'];
        unset($resultClient);
        $results['cert'] = openssl_x509_parse($response['ssl']['peer_certificate'], true);

        if (count($response["ssl"]["peer_certificate_chain"]) > 1) {
            foreach ($response["ssl"]["peer_certificate_chain"] as $cert) {
                $parsedCert = openssl_x509_parse($cert, true);
                $isChain = !($parsedCert['hash'] === $results['cert']['hash']);
                if ($isChain === true) {
                    array_push($results['full_chain'], $parsedCert);
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
