<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Crypto;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use OpenID4VC\SIOPv2\Exception\CryptoException;
use OpenID4VC\SIOPv2\Util\Json;

final class OpenSslSigner implements SignerInterface
{
    /**
     * @param \OpenSSLAsymmetricKey|string|Jwk $privateKey
     */
    public function __construct(
        private readonly mixed $privateKey,
        private readonly string $algorithm
    ) {
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     */
    public function sign(array $header, array $payload): string
    {
        $header['alg'] = $this->algorithm;
        $jwk = $this->createPrivateJwk();
        $builder = new JWSBuilder($this->createAlgorithmManager());
        $jws = $builder
            ->create()
            ->withPayload(Json::encode($payload))
            ->addSignature($jwk, $header)
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private function createAlgorithmManager(): AlgorithmManager
    {
        return new AlgorithmManager([
            new ES256(),
            new RS256(),
        ]);
    }

    private function createPrivateJwk(): \Jose\Component\Core\JWK
    {
        if ($this->privateKey instanceof Jwk) {
            return $this->privateKey->toJose();
        }

        return JWKFactory::createFromKey($this->normalizePrivateKey($this->privateKey), null, ['use' => 'sig']);
    }

    private function normalizePrivateKey(mixed $privateKey): string
    {
        if (is_string($privateKey)) {
            return $privateKey;
        }

        if ($privateKey instanceof \OpenSSLAsymmetricKey) {
            $exportedKey = null;
            if (!openssl_pkey_export($privateKey, $exportedKey) || !is_string($exportedKey)) {
                throw new CryptoException('OpenSSL could not export the private key.');
            }

            return $exportedKey;
        }

        throw new CryptoException('Unsupported private key input.');
    }
}
