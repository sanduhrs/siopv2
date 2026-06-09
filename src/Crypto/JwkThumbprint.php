<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Crypto;

final class JwkThumbprint
{
    public static function thumbprint(Jwk $jwk): string
    {
        return $jwk->toJose()->thumbprint('sha256');
    }
}
