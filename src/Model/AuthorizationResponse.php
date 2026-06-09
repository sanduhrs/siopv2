<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Model;

final class AuthorizationResponse
{
    /**
     * @param array<string, string> $parameters
     */
    public function __construct(
        public readonly string $redirectUri,
        public readonly array $parameters
    ) {
    }
}
