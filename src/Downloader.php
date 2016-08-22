<?php

namespace Spatie\SslCertificate;

use Spatie\SslCertificate\Exceptions\CouldNotDownloadCertificate;
use Spatie\SslCertificate\SslClient;
use Throwable;

class Downloader
{

    public static function downloadCertificateFromUrl(string $url, int $timeout = 30): array
    {
        // Trusted variable to keep track of SSL trust
        $results = [
            'cert' => null,
            'full_chain' => null,
            'trusted' => true
        ];
        $sslConfig = SslConfig::configSecure($timeout);
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
                $sslConfig->getStream()
            );
        } catch (Throwable $thrown) {
            unset($sslConfig, $client);
            // As the URL failed varification we set to false
            $results['trusted'] = false;
            $sslConfig = SslConfig::configInsecure($timeout);

            try {
                $client = stream_socket_client(
                    "ssl://{$hostName}:{$port}",
                    $errorNumber,
                    $errorDescription,
                    $timeout,
                    STREAM_CLIENT_CONNECT,
                    $sslConfig->getStream()
                );
                $response = stream_context_get_params($client);
                dd(openssl_x509_parse($response['options']['ssl']['peer_certificate']));

            } catch (Throwable $thrown) {
                dd($thrown);
                if (str_contains($thrown->getMessage(), 'getaddrinfo failed')) {
                    throw CouldNotDownloadCertificate::hostDoesNotExist($hostName);
                }

                if (str_contains($thrown->getMessage(), 'error:14090086')) {
                    throw CouldNotDownloadCertificate::noCertificateInstalled($hostName);
                }

                throw CouldNotDownloadCertificate::unknownError($hostName, $thrown->getMessage());
            }
        }

        $response = stream_context_get_params($client);
        $results['cert'] = openssl_x509_parse($response['options']['ssl']['peer_certificate']);

        if (count($response["options"]["ssl"]["peer_certificate_chain"]) > 1) {
            $results['full_chain'] = [];
            foreach($response["options"]["ssl"]["peer_certificate_chain"] as $cert)
            {
                array_push($results['full_chain'],openssl_x509_parse($cert));
            }
        }

        return $results;
    }
}
