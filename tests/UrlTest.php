<?php

namespace LiquidWeb\SslCertificate\Test;

use PHPUnit_Framework_TestCase;
use LiquidWeb\SslCertificate\Exceptions\InvalidUrl;
use LiquidWeb\SslCertificate\Url;

class UrlTest extends PHPUnit_Framework_TestCase
{
    /** @test */
    public function it_can_determine_a_host_name()
    {
        $url = new Url('https://spatie.be/opensource');

        $this->assertSame('spatie.be', $url->getHostName());
    }

    /** @test */
    public function it_can_determine_a_host_name_when_not_specifying_a_protocol()
    {
        $url = new Url('spatie.be');

        $this->assertSame('spatie.be', $url->getHostName());
    }

    /** @test */
    public function it_throws_an_exception_when_creating_an_url_from_an_empty_string()
    {
        $this->expectException(InvalidUrl::class);

        new Url('');
    }
}
