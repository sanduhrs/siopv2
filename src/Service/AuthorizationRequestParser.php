<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Service;

use OpenID4VC\SIOPv2\Model\AuthorizationRequest;
use OpenID4VC\SIOPv2\Model\RelyingPartyMetadata;
use OpenID4VC\SIOPv2\Util\Json;

final class AuthorizationRequestParser
{
    /**
     * @param array<string, mixed> $parameters
     */
    public function parse(array $parameters): AuthorizationRequest
    {
        $clientMetadata = null;
        if (isset($parameters['client_metadata']) && is_string($parameters['client_metadata'])) {
            $metadata = Json::decodeObject($parameters['client_metadata']);
            $clientMetadata = new RelyingPartyMetadata(
                subjectSyntaxTypesSupported: $this->stringList(
                    $metadata['subject_syntax_types_supported'] ?? []
                ),
                idTokenSigningAlgValuesSupported: $this->stringList(
                    $metadata['id_token_signing_alg_values_supported'] ?? []
                ),
                additionalParameters: $metadata
            );
        }

        return new AuthorizationRequest(
            clientId: $this->optionalString($parameters['client_id'] ?? null) ?? '',
            redirectUri: $this->optionalString($parameters['redirect_uri'] ?? null) ?? '',
            responseTypes: $this->splitBySpaces($parameters['response_type'] ?? ''),
            scopes: $this->splitBySpaces($parameters['scope'] ?? ''),
            nonce: $this->optionalString($parameters['nonce'] ?? null) ?? '',
            state: $this->optionalString($parameters['state'] ?? null),
            clientMetadata: $clientMetadata,
            clientMetadataUri: $this->optionalString($parameters['client_metadata_uri'] ?? null),
            additionalParameters: $parameters
        );
    }

    /**
     * @param mixed $value
     * @return list<string>
     */
    private function splitBySpaces(mixed $value): array
    {
        if (!is_string($value) || trim($value) === '') {
            return [];
        }

        return array_values(array_filter(array_map('trim', explode(' ', $value))));
    }

    /**
     * @param mixed $value
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        return array_values(
            array_filter(
                array_map($this->optionalString(...), $value),
                static fn (mixed $item): bool => is_string($item)
            )
        );
    }

    private function optionalString(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }
}
