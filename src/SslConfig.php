<?php

namespace Spatie\SslCertificate;

class SslConfig
{

    /**
     * The stream settings for the client.
     *
     * @return A stream context resource.
     */
    protected $streamContext;

    public static function configSecure(): SslConfig
    {
        $streamContext = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'capture_peer_cert_chain' => true,
            ],
        ]);

        return new static($streamContext);
    }

    public static function configInsecure(): SslConfig
    {
        $streamContext = stream_context_create([
            'ssl' => [
                'allow_self_signed' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'capture_peer_cert' => true,
                'capture_peer_cert_chain' => true,
            ],
        ]);

        return new static($streamContext);
    }

    public function __construct($streamContext)
    {
        $this->streamContext = $streamContext;
    }

    public function getStream()
    {
        return $this->streamContext;
    }

}
