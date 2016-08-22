# A class to validate SSL certificates

The class provided by this package makes it incredibly easy to query the properties on an ssl certificate. Here's an example:

```php
$certificate = SslCertificate::createForHostName('spatie.be');

$certificate->getIssuer(); // returns "Let's Encrypt Authority X3"
$certificate->isValid(); // returns true if the certificate is currently valid
$certificate->expirationDate(); // returns an instance of Carbon
$certificate->expirationDate()->diffInDays(); // returns an int
$certificate->getSignatureAlgorithm(); // returns a string
```

## Installation

You can install the package via composer:

```bash
composer require spatie/ssl-certificate
```

## Important notice

Currently this package [does not check](https://github.com/spatie/ssl-certificate/blob/master/src/SslCertificate.php#L63-L74) if the certificate is signed by a trusted authority. We'll add this check soon in a next point release.

## Usage

You can create an instance of `Spatie\SslCertificate\SslCertificate` with this named constructor:

```php
$certificate = SslCertificate::createForHostName('spatie.be');
```

If the given `hostName` is invalid `Spatie\SslCertificate\InvalidUrl` will be thrown.

If the given `hostName` is valid but there was a problem downloading the certifcate `Spatie\SslCertificate\CouldNotDownloadCertificate` will be thrown.

### Getting the issuer name

```php
$certificate->getIssuer(); // returns "Let's Encrypt Authority X3"
```

### Getting the domain name

Returns the primary domain name for the certificate

```php
$certificate->getDomain(); // returns "spatie.be"
```

### Getting the certificate's signing algorithm

Returns the algorithm used for signing the certificate

```php
$certificate->getSignatureAlgorithm(); // returns "RSA-SHA256"
```

### Getting the additional domain names

A certificate can cover multiple (sub)domains. Here's how to get them.

```php
$certificate->getAdditionalDomains(); // returns ["spatie.be", "www.spatie.be]
```

A domain name return with this method can start with `*` meaning it is valid for all subdomains of that domain.

### Getting the date when the certificate becomes valid

```php
$this->certificate->validFromDate(); // returns an instance of Carbon
```

### Getting the expiration date

```php
$this->certificate->expirationDate(); // returns an instance of Carbon
```

### Determining if the certificate is still valid

Returns true if the current Date and time is between `validFromDate` and `expirationDate`.

```php
$this->certificate->isValid(); // returns a boolean
```

You also use this method to determine if a given domain is covered by the certificate. Of course it'll keep checking if the current Date and time is between `validFromDate` and `expirationDate`.

```php
$this->certificate->isValid('spatie.be'); // returns true;
$this->certificate->isValid('laravel.com'); // returns false;
```

### Determining if the certificate is still valid until a given date

Returns true if the certificate is valid and if the `expirationDate` is before the given date.

```php
$this->certificate->isValidUntil(Carbon::now()->addDays(7)); // returns a boolean
```

### Determining if the certificate is expired

```php
$this->certificate->isExpired(); // returns a boolean if expired
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Testing

``` bash
$ composer test
```

Note: When working to test your implementation of this library you can use [BadSSL](https://badssl.com/) to simulate various SSL scenarios.

## Credits

- [Freek Van der Herten](https://github.com/freekmurze) - Original creator
- [All Contributors](../../contributors)

The helper functions and tests were copied from the [Laravel Framework](https://github.com/laravel/framework).

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
