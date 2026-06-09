<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Model;

final class AuthorizationRequest
{
    /**
     * @param list<string> $responseTypes
     * @param list<string> $scopes
     * @param array<string, mixed> $additionalParameters
     */
    public function __construct(
        public readonly string $clientId,
        public readonly string $redirectUri,
        public readonly array $responseTypes,
        public readonly array $scopes,
        public readonly string $nonce,
        public readonly ?string $state = null,
        public readonly ?RelyingPartyMetadata $clientMetadata = null,
        public readonly ?string $clientMetadataUri = null,
        public readonly array $additionalParameters = []
    ) {
    }
}
