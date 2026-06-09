<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Model;

use OpenID4VC\SIOPv2\Crypto\Jwk;

final class ResolvedDidDocument
{
    public function __construct(
        public readonly string $id,
        public readonly Jwk $publicKeyJwk
    ) {
    }
}
