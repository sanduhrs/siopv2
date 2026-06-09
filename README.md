# OpenID4VC SIOPv2

Structured PHP library for implementing a Self-Issued OpenID Provider v2 in PHP applications and CMS integrations.

## Scope

This package focuses on the core SIOPv2 building blocks:

- Authorization request parsing and validation.
- RP metadata validation relevant to SIOPv2.
- Self-issued ID token creation.
- Compact JWS handling through `web-token/jwt-framework` with `ES256` and `RS256`.
- JWK thumbprint subject syntax support.
- RP-side self-issued ID token validation.
- DID-based subject validation through a pluggable resolver interface.

The current version deliberately keeps transport, storage, and DID resolution outside the package so CMS integrations can supply their own implementations.

## Install

```bash
composer require openid4vc/siopv2
```

## Quick Start

```php
<?php

declare(strict_types=1);

use OpenID4VC\SIOPv2\Crypto\Jwk;
use OpenID4VC\SIOPv2\Crypto\OpenSslSigner;
use OpenID4VC\SIOPv2\SelfIssuedOpenIdProvider;
use OpenID4VC\SIOPv2\Subject\JwkThumbprintSubjectIdentifier;

$provider = new SelfIssuedOpenIdProvider();

$request = $provider->parseAuthorizationRequest($_GET);
$provider->validateAuthorizationRequest($request);

$privateKey = openssl_pkey_get_private(file_get_contents(__DIR__ . '/wallet-private.pem'));
$publicJwk = Jwk::fromArray([
    'kty' => 'EC',
    'crv' => 'P-256',
    'x' => '...',
    'y' => '...',
]);

$subject = new JwkThumbprintSubjectIdentifier($publicJwk);
$signer = new OpenSslSigner($privateKey, 'ES256');

$response = $provider->createAuthorizationResponse($request, $subject, $signer);
$redirectUri = (new \OpenID4VC\SIOPv2\Service\AuthorizationResponseFactory())->buildRedirectUri($response);
```

## Architecture

- [`SelfIssuedOpenIdProvider`](src/SelfIssuedOpenIdProvider.php) is the façade for typical OP-side use.
- [`Service`](src/Service) contains protocol logic.
- [`Crypto`](src/Crypto) contains JWK wrappers, JWS adapters, thumbprints, and `web-token/jwt-framework` integration.
- [`Subject`](src/Subject) models supported SIOPv2 subject syntaxes.
- [`DidDocumentResolverInterface`](src/Did/DidDocumentResolverInterface.php) keeps DID resolution pluggable.

## PSR and PER Usage

This library uses and supports the following PHP-FIG standards:

- `PSR-4`: the package is distributed as a standard Composer library with PSR-4 autoloading for `OpenID4VC\\SIOPv2\\`.
- `psr/clock` (`PSR-20`): time-dependent services depend on [`Psr\Clock\ClockInterface`](src/Clock/SystemClock.php) and ship with [`SystemClock`](src/Clock/SystemClock.php) and [`FrozenClock`](src/Clock/FrozenClock.php) implementations.
- `psr/log` (`PSR-3`): provider and validation services accept [`Psr\Log\LoggerInterface`](src/SelfIssuedOpenIdProvider.php) and default to `NullLogger` when no logger is provided.
- `PSR-1`: the source code follows the PSR-1 basic coding standard as part of the coding-style baseline.
- `PSR-12`: PHPCS uses PSR-12 as the base ruleset for enforceable style checks.
- `PER Coding Style 3.0`: the project style configuration is aligned with PER 3.0 semantics where PHPCS can enforce them, most notably around line-length behavior.

This library does not currently expose APIs based on PSR-6, PSR-7, PSR-14, PSR-15, PSR-17, or PSR-18. Those can be added later if we decide to standardize caching, HTTP transport, or event integration.

## Notes

- `request` and `request_uri` request objects are not implemented in this version.
- Dynamic retrieval through `client_metadata_uri` is not implemented in this version.
- `ES256` and `RS256` are implemented. Other JOSE algorithms can be added through `SignerInterface` and `VerifierInterface`.
- JOSE signing, compact JWS serialization, JWK handling, and verification are backed by `web-token/jwt-framework`.
- `PSR-3` logging hooks are available in the provider, request validator, ID token builder, response factory, and ID token validator.
- For JWK thumbprint subjects, the ID token `sub` is derived from the RFC 7638 thumbprint of `sub_jwk`.
- For DID subjects, the validator expects a resolver that returns the correct verification key for the requested DID and `kid`.

## Spec Status

Specification coverage notes and currently missing/out-of-scope features are tracked in:
[/home/sanduhrs/Workspace/PHP/openid4vc/LIBRARY_SPEC_STATUS.md](/home/sanduhrs/Workspace/PHP/openid4vc/LIBRARY_SPEC_STATUS.md)

## Run Tests

```bash
composer test
```

## Run Test Coverage

```bash
composer test:coverage
```

Or run PHPUnit directly:

```bash
vendor/bin/phpunit
```

## Run Style Checks

```bash
composer lint
```

Or run PHP_CodeSniffer directly:

```bash
vendor/bin/phpcs --runtime-set ignore_warnings_on_exit 1
```

This project uses a PHPCS ruleset aligned with PER Coding Style 3.0. PHPCS 4 does not currently ship an official `PER-CS3.0` standard, so the local [phpcs.xml.dist](/home/sanduhrs/Workspace/PHP/OpenID4VC/phpcs.xml.dist:1) uses `PSR12` as the base and applies PER 3.0 line-length semantics.
