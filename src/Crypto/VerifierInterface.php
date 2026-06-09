<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Crypto;

interface VerifierInterface
{
    public function verify(string $compactJws, Jwk $publicKey): bool;
}
