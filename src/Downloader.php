<?php

namespace Spatie\SslCertificate;

use Spatie\SslCertificate\Exceptions\CouldNotDownloadCertificate;
use Spatie\SslCertificate\StreamConfig;
use Throwable;

class Downloader
{

    public static function downloadCertificateFromUrl(string $url, int $timeout = 30): array
    {
        // Trusted variable to keep track of SSL trust
        $trusted = true;
        $sslConfig = StreamConfig::configSecure($timeout);
        $parsedUrl = new Url($url);
        $hostName = $parsedUrl->getHostName();
        $port = $parsedUrl->getPort();

        try {
            $client = stream_socket_client(
                "ssl://{$hostName}:{$port}",
                $errorNumber,
                $errorDescription,
                $timeout,
                STREAM_CLIENT_CONNECT,
                $sslConfig->getContext()
            );
        } catch (Throwable $thrown) {
            // Unset previous vars just to keep things legit
            unset($sslConfig, $client);
            // Try agian in insecure mode
            $sslConfig = StreamConfig::configInsecure($timeout);

            try {
                // As the URL failed varification we set to false
                $trusted = false;
                $client = stream_socket_client(
                    "ssl://{$hostName}:{$port}",
                    $errorNumber,
                    $errorDescription,
                    $timeout,
                    STREAM_CLIENT_CONNECT,
                    $sslConfig->getContext()
                );
                $domainIp = gethostbyname( $hostName );

                return self::prepareCertificateResponse($client, $trusted, $domainIp);
            } catch (Throwable $thrown) {
                if (str_contains($thrown->getMessage(), 'getaddrinfo failed')) {
                    throw CouldNotDownloadCertificate::hostDoesNotExist($hostName);
                }

                if (str_contains($thrown->getMessage(), 'error:14090086')) {
                    throw CouldNotDownloadCertificate::noCertificateInstalled($hostName);
                }

                throw CouldNotDownloadCertificate::unknownError($hostName, $thrown->getMessage());
            }
        }
        $domainIp = gethostbyname( $hostName );

        return self::prepareCertificateResponse($client, $trusted, $domainIp);
    }

    private static function prepareCertificateResponse($client, bool $trusted, string $domainIp): array
    {
        $results = [
            'cert' => null,
            'full_chain' => [],
            'trusted' => $trusted,
            'resolves-to' => $domainIp
        ];
        $response = stream_context_get_params($client);
        $results['cert'] = openssl_x509_parse($response['options']['ssl']['peer_certificate']);

        if (count($response["options"]["ssl"]["peer_certificate_chain"]) > 1) {
            foreach($response["options"]["ssl"]["peer_certificate_chain"] as $cert)
            {
                array_push($results['full_chain'],openssl_x509_parse($cert));
            }
        }

        return $results;
    }

    public static function downloadRevocationListFromUrl(string $url): string
    {
        //$rawCrl = shell_exec("curl {$url} | openssl crl -inform DER -outform PEM");
        $sslConfig = StreamConfig::configCrl();
        //$stream = file_get_contents($url);
        //$stream = fopen('/home/dan/public_html/tools/public/crl-2.pem', 'r', $sslConfig$sslConfig);
        var_dump($stream);
        $data = openssl_x509_read($stream);
        dd( $data );
        // actual data at $url
        $data = stream_get_contents($stream);
        dd( $data );
        var_dump( $data );
        $hurp = openssl_x509_read($data);
        dd( $hurp );
        $herp = openssl_x509_read( $data );
        dd( $herp );
        dd( $stream );

        $rawCrl = shell_exec("curl {$url} | openssl crl -inform DER -outform PEM");
        dd( openssl_x509_read($rawCrl) );
        return $rawCrl;
    }

}
