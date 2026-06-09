<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Util;

use OpenID4VC\SIOPv2\Exception\CryptoException;

final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode(string $data): string
    {
        $padding = strlen($data) % 4;
        if ($padding > 0) {
            $data .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new CryptoException('Invalid base64url payload.');
        }

        return $decoded;
    }
}
