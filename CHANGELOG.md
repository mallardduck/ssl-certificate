# Changelog

All notable changes to `ssl-certificate` will be documented in this file

## 1.0.0 - 2016-09-19

- package forked
- reset semver
- removed previous package tags
- added `SslChain.php`
- added `SslRevocationList.php`
- added `StreamConfig.php`
- added `IssuerMeta.php`
- added the following functions:
    - InvalidUrl `couldNotResolveDns`
    - CouldNotDownloadCertificate `failedHandshake`
    - CouldNotDownloadCertificate `connectionTimeout`
    - Downloader `prepareCertificateResponse` - private
    - Downloader `downloadRevocationListFromUrl`
    - Url `getValidatedURL`
    - Url `getPort`
    - Url `getTestURL`
    - Url `getIp`
    - SslCertificate `extractCrlLinks` - private
    - SslCertificate `setcrlLinks` - private
    - SslCertificate `getRevokedDate` - private
    - SslCertificate `parseCertChains` - private
    - SslCertificate `hasSslChain`
    - SslCertificate `getTestedDomain`
    - SslCertificate `getCertificateChains`
    - SslCertificate `getSerialNumber`
    - SslCertificate `hasCrlLink`
    - SslCertificate `getCrlLinks`
    - SslCertificate `getCrl`
    - SslCertificate `isClrRevoked`
    - SslCertificate `getResolvedIp`
    - SslCertificate `getConnectionMeta`
    - SslCertificate `isTrusted`
- added `SslChainTest.php`
- added various stubs for Testing
- updated all tests to maintain high coverage levels

# Original package history

## 1.2.0 - 2016-08-20

- added `getSignatureAlgorithm`

## 1.1.0 - 2016-07-29

- added `isValidUntil`

## 1.0.0 - 2016-07-28

- initial release
