<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Crypto;

use Jose\Component\Signature\Serializer\CompactSerializer;
use OpenID4VC\SIOPv2\Util\Base64Url;
use OpenID4VC\SIOPv2\Util\Json;

final class Jws
{
    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     */
    public static function encode(array $header, array $payload, SignerInterface $signer): string
    {
        return $signer->sign($header, $payload);
    }

    /**
     * @return array{
     *     header: array<string, mixed>,
     *     payload: array<string, mixed>,
     *     signingInput: string,
     *     signature: string
     * }
     */
    public static function decode(string $compactJws): array
    {
        $serializer = new CompactSerializer();
        $jws = $serializer->unserialize($compactJws);
        $signature = $jws->getSignature(0);
        $parts = explode('.', $compactJws);
        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        return [
            'header' => $signature->getProtectedHeader(),
            'payload' => Json::decodeObject($jws->getPayload() ?? '{}'),
            'signingInput' => $encodedHeader . '.' . $encodedPayload,
            'signature' => Base64Url::decode($encodedSignature),
        ];
    }
}
