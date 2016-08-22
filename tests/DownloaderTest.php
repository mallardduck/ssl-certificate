<?php

namespace Spatie\SslCertificate\Test;

use PHPUnit_Framework_TestCase;
use Spatie\SslCertificate\Downloader;
use Spatie\SslCertificate\Exceptions\InvalidUrl;
use Spatie\SslCertificate\Exceptions\CouldNotDownloadCertificate;

class DownloaderTest extends PHPUnit_Framework_TestCase
{
    /** @test */
    public function it_can_download_a_certificate_from_a_host_name()
    {
        $downloadResults = Downloader::downloadCertificateFromUrl('spatie.be');

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
    public function it_throws_an_exception_when_downloading_a_certificate_from_a_host_that_contains_none()
    {
        $this->expectException(CouldNotDownloadCertificate::class);

        Downloader::downloadCertificateFromUrl('www.kutfilm.be:80');
    }
}
