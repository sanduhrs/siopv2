<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Crypto;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use OpenID4VC\SIOPv2\Exception\CryptoException;

final class OpenSslVerifier implements VerifierInterface
{
    public function verify(string $compactJws, Jwk $publicKey): bool
    {
        try {
            $serializer = new CompactSerializer();
            $jws = $serializer->unserialize($compactJws);
            $verifier = new JWSVerifier(new AlgorithmManager([
                new ES256(),
                new RS256(),
            ]));

            return $verifier->verifyWithKey($jws, $publicKey->toJose(), 0);
        } catch (\Throwable $exception) {
            throw new CryptoException('JWS verification failed.', 0, $exception);
        }
    }
}
