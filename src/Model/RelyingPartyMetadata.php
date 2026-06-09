<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Model;

final class RelyingPartyMetadata
{
    /**
     * @param list<string> $subjectSyntaxTypesSupported
     * @param list<string> $idTokenSigningAlgValuesSupported
     * @param array<string, mixed> $additionalParameters
     */
    public function __construct(
        public readonly array $subjectSyntaxTypesSupported = ['urn:ietf:params:oauth:jwk-thumbprint'],
        public readonly array $idTokenSigningAlgValuesSupported = ['ES256'],
        public readonly array $additionalParameters = []
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_merge(
            [
                'subject_syntax_types_supported' => $this->subjectSyntaxTypesSupported,
                'id_token_signing_alg_values_supported' => $this->idTokenSigningAlgValuesSupported,
            ],
            $this->additionalParameters
        );
    }
}
