<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Service;

use OpenID4VC\SIOPv2\Exception\InvalidMetadata;
use OpenID4VC\SIOPv2\Model\RelyingPartyMetadata;

final class RelyingPartyMetadataValidator
{
    /**
     * @param list<string> $supportedSubjectSyntaxTypes
     * @param list<string> $supportedAlgorithms
     */
    public function __construct(
        private readonly array $supportedSubjectSyntaxTypes = ['urn:ietf:params:oauth:jwk-thumbprint'],
        private readonly array $supportedAlgorithms = ['ES256']
    ) {
    }

    public function validate(RelyingPartyMetadata $metadata): void
    {
        if ($metadata->subjectSyntaxTypesSupported === []) {
            throw new InvalidMetadata('RP metadata must declare subject_syntax_types_supported.');
        }

        if ($metadata->idTokenSigningAlgValuesSupported === []) {
            throw new InvalidMetadata('RP metadata must declare id_token_signing_alg_values_supported.');
        }

        if (count(array_intersect($metadata->subjectSyntaxTypesSupported, $this->supportedSubjectSyntaxTypes)) === 0) {
            throw new InvalidMetadata(
                'RP metadata does not support any subject syntax type implemented by this provider.'
            );
        }

        if (count(array_intersect($metadata->idTokenSigningAlgValuesSupported, $this->supportedAlgorithms)) === 0) {
            throw new InvalidMetadata(
                'RP metadata does not support any ID token signing algorithm implemented by this provider.'
            );
        }
    }
}
