<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Util;

use JsonException;
use OpenID4VC\SIOPv2\Exception\SioPv2Exception;

final class Json
{
    /**
     * @param array<string, mixed> $value
     */
    public static function encode(array $value): string
    {
        try {
            return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $exception) {
            throw new SioPv2Exception('JSON encoding failed.', 0, $exception);
        }
    }

    /**
     * @return array<string, mixed>
     */
    public static function decodeObject(string $json): array
    {
        try {
            $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new SioPv2Exception('JSON decoding failed.', 0, $exception);
        }

        if (!is_array($decoded)) {
            throw new SioPv2Exception('JSON value must decode to an object.');
        }

        foreach (array_keys($decoded) as $key) {
            if (!is_string($key)) {
                throw new SioPv2Exception('JSON object keys must be strings.');
            }
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
