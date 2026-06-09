<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Subject;

use OpenID4VC\SIOPv2\Crypto\Jwk;

final class DidSubjectIdentifier implements SubjectIdentifierInterface
{
    public function __construct(
        private readonly string $did,
        private readonly ?Jwk $publicKeyJwk = null
    ) {
    }

    public function subject(): string
    {
        return $this->did;
    }

    public function syntaxType(): string
    {
        return 'did';
    }

    public function publicKeyJwk(): ?Jwk
    {
        return $this->publicKeyJwk;
    }
}
