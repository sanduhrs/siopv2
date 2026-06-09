<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Crypto;

use Jose\Component\Core\JWK as JoseJwk;
use OpenID4VC\SIOPv2\Exception\CryptoException;

final class Jwk
{
    public function __construct(
        private readonly JoseJwk $jwk
    ) {
        $kty = $this->jwk->all()['kty'] ?? null;
        if (!is_string($kty)) {
            throw new CryptoException('A JWK must contain a string kty parameter.');
        }
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public static function fromArray(array $parameters): self
    {
        return new self(new JoseJwk($parameters));
    }

    public static function fromJose(JoseJwk $jwk): self
    {
        return new self($jwk);
    }

    public function get(string $name): mixed
    {
        return $this->has($name) ? $this->jwk->get($name) : null;
    }

    public function kty(): string
    {
        $kty = $this->jwk->get('kty');
        if (!is_string($kty)) {
            throw new CryptoException('A JWK must contain a string kty parameter.');
        }

        return $kty;
    }

    public function has(string $name): bool
    {
        return $this->jwk->has($name);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $values = $this->jwk->all();
        foreach (array_keys($values) as $key) {
            if (!is_string($key)) {
                throw new CryptoException('A JWK must use string keys.');
            }
        }

        /** @var array<string, mixed> $values */
        return $values;
    }

    public function toJose(): JoseJwk
    {
        return $this->jwk;
    }

    public function isPublic(): bool
    {
        return !$this->has('d');
    }
}
