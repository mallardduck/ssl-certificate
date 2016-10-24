<?php

namespace LiquidWeb\SslCertificate\Test;

use PHPUnit_Framework_TestCase;
use LiquidWeb\SslCertificate\Downloader;
use LiquidWeb\SslCertificate\Exceptions\InvalidUrl;
use LiquidWeb\SslCertificate\Exceptions\CouldNotDownloadCertificate;

class DownloaderTest extends PHPUnit_Framework_TestCase
{
    /** @test */
    public function it_can_download_a_certificate_from_a_host_name()
    {
        $downloadResults = Downloader::downloadCertificateFromUrl('spatie.be', 10);

        $this->assertTrue(is_array($downloadResults));
        $this->assertTrue(is_array($downloadResults['cert']));

        $this->assertSame('/CN=spatie.be', $downloadResults['cert']['name']);
    }

    /** @test */
    public function it_throws_an_exception_for_non_existing_host()
    {
        $this->expectException(InvalidUrl::class);

        Downloader::downloadCertificateFromUrl('spatie-non-existing.be');
    }

    /** @test */
    public function it_throws_an_exception_when_downloading_a_certificate_from_wrong_port()
    {
        $this->expectException(CouldNotDownloadCertificate::class);

        Downloader::downloadCertificateFromUrl('www.kutfilm.be:80');
    }

    /** @test */
    public function it_throws_an_exception_when_downloading_a_certificate_from_an_outdated_host()
    {
        $this->expectException(CouldNotDownloadCertificate::class);

        Downloader::downloadCertificateFromUrl('rc4.badssl.com', 10);
    }

    /** @test */
    public function it_throws_a_timeout_exception_when_downloading_a_certificate_from_a_fake_location()
    {
        $this->expectException(CouldNotDownloadCertificate::class);

        Downloader::downloadCertificateFromUrl('10.0.0.1', 3);
    }
}
