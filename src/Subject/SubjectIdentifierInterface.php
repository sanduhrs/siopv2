<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Subject;

use OpenID4VC\SIOPv2\Crypto\Jwk;

interface SubjectIdentifierInterface
{
    public function subject(): string;

    public function syntaxType(): string;

    public function publicKeyJwk(): ?Jwk;
}
