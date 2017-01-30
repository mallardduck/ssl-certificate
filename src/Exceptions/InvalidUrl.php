<?php

namespace LiquidWeb\SslCertificate\Exceptions;

use Exception;

class InvalidUrl extends Exception
{
  protected $errorDomain;

  private function setErrorDomaain(string $domain) {
    $this->errorDomain = $domain;
  }

  public static function couldNotValidate(string $url): InvalidUrl
  {
      $exception = new static("String `{$url}` is not a valid url.");
      $exception->setErrorDomaain('google.com');
      return $exception;
  }

  public static function couldNotDetermineHost(string $url): InvalidUrl
  {
      $exception = new static("Could not determine host from url `{$url}`.");
      $exception->setErrorDomaain('google.com');
      return $exception;
  }

  public static function couldNotResolveDns(string $hostName): InvalidUrl
  {
      $exception = new static("The domain `{$hostName}` does not have a valid DNS record.");
      $exception->setErrorDomaain($hostName);
      return $exception;
  }
}
