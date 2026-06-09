<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Service;

use OpenID4VC\SIOPv2\Exception\InvalidAuthorizationRequest;
use OpenID4VC\SIOPv2\Model\AuthorizationRequest;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class AuthorizationRequestValidator
{
    public function __construct(
        private readonly RelyingPartyMetadataValidator $metadataValidator = new RelyingPartyMetadataValidator(),
        private readonly LoggerInterface $logger = new NullLogger()
    ) {
    }

    public function validate(AuthorizationRequest $request): void
    {
        if ($request->clientId === '') {
            $this->logger->warning('Authorization request rejected: missing client_id.');
            throw new InvalidAuthorizationRequest('client_id is required.');
        }

        if ($request->redirectUri === '') {
            $this->logger->warning('Authorization request rejected: missing redirect_uri.');
            throw new InvalidAuthorizationRequest('redirect_uri is required.');
        }

        if ($request->nonce === '') {
            $this->logger->warning('Authorization request rejected: missing nonce.');
            throw new InvalidAuthorizationRequest('nonce is required.');
        }

        if (!in_array('openid', $request->scopes, true)) {
            $this->logger->warning('Authorization request rejected: missing openid scope.');
            throw new InvalidAuthorizationRequest('scope must contain openid.');
        }

        if (!in_array('id_token', $request->responseTypes, true)) {
            $this->logger->warning('Authorization request rejected: missing id_token response type.');
            throw new InvalidAuthorizationRequest('response_type must contain id_token.');
        }

        if (isset($request->additionalParameters['request']) || isset($request->additionalParameters['request_uri'])) {
            $this->logger->warning('Authorization request rejected: request objects are not implemented.');
            throw new InvalidAuthorizationRequest(
                'Signed request objects are not implemented by this library version.'
            );
        }

        if (filter_var($request->redirectUri, FILTER_VALIDATE_URL) === false) {
            $this->logger->warning('Authorization request rejected: invalid redirect_uri.', [
                'redirect_uri' => $request->redirectUri,
            ]);
            throw new InvalidAuthorizationRequest('redirect_uri must be a valid absolute URI.');
        }

        if ($request->clientMetadata !== null && $request->clientMetadataUri !== null) {
            $this->logger->warning('Authorization request rejected: both client_metadata and client_metadata_uri set.');
            throw new InvalidAuthorizationRequest('client_metadata and client_metadata_uri must not both be present.');
        }

        if ($request->clientId === $request->redirectUri && $request->clientMetadata !== null) {
            $this->metadataValidator->validate($request->clientMetadata);

            $this->logger->info('Authorization request validated with inline client metadata.', [
                'client_id' => $request->clientId,
            ]);
            return;
        }

        if ($request->clientMetadata !== null) {
            $this->metadataValidator->validate($request->clientMetadata);
        }

        $this->logger->info('Authorization request validated.', [
            'client_id' => $request->clientId,
        ]);
    }
}
