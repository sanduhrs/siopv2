<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Crypto;

interface SignerInterface
{
    public function algorithm(): string;

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     */
    public function sign(array $header, array $payload): string;
}
