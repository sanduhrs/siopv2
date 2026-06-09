<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Subject;

use OpenID4VC\SIOPv2\Crypto\Jwk;
use OpenID4VC\SIOPv2\Crypto\JwkThumbprint;

final class JwkThumbprintSubjectIdentifier implements SubjectIdentifierInterface
{
    public function __construct(
        private readonly Jwk $publicKeyJwk
    ) {
    }

    public function subject(): string
    {
        return JwkThumbprint::thumbprint($this->publicKeyJwk);
    }

    public function syntaxType(): string
    {
        return 'urn:ietf:params:oauth:jwk-thumbprint';
    }

    public function publicKeyJwk(): Jwk
    {
        return $this->publicKeyJwk;
    }
}
