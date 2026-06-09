<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Model;

final class ProviderMetadata
{
    /**
     * @param list<string> $responseTypesSupported
     * @param list<string> $scopesSupported
     * @param list<string> $subjectTypesSupported
     * @param list<string> $idTokenSigningAlgValuesSupported
     * @param list<string> $requestObjectSigningAlgValuesSupported
     * @param list<string> $subjectSyntaxTypesSupported
     * @param list<string> $idTokenTypesSupported
     * @param array<string, mixed> $additionalParameters
     */
    public function __construct(
        public readonly string $authorizationEndpoint = 'openid:',
        public readonly array $responseTypesSupported = ['id_token'],
        public readonly array $scopesSupported = ['openid'],
        public readonly array $subjectTypesSupported = ['pairwise'],
        public readonly array $idTokenSigningAlgValuesSupported = ['ES256'],
        public readonly array $requestObjectSigningAlgValuesSupported = ['ES256'],
        public readonly array $subjectSyntaxTypesSupported = ['urn:ietf:params:oauth:jwk-thumbprint'],
        public readonly array $idTokenTypesSupported = ['subject_signed_id_token'],
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
                'authorization_endpoint' => $this->authorizationEndpoint,
                'response_types_supported' => $this->responseTypesSupported,
                'scopes_supported' => $this->scopesSupported,
                'subject_types_supported' => $this->subjectTypesSupported,
                'id_token_signing_alg_values_supported' => $this->idTokenSigningAlgValuesSupported,
                'request_object_signing_alg_values_supported' => $this->requestObjectSigningAlgValuesSupported,
                'subject_syntax_types_supported' => $this->subjectSyntaxTypesSupported,
                'id_token_types_supported' => $this->idTokenTypesSupported,
            ],
            $this->additionalParameters
        );
    }
}
