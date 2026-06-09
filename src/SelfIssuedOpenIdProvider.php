<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2;

use OpenID4VC\SIOPv2\Crypto\SignerInterface;
use OpenID4VC\SIOPv2\Model\AuthorizationRequest;
use OpenID4VC\SIOPv2\Model\AuthorizationResponse;
use OpenID4VC\SIOPv2\Service\AuthorizationRequestParser;
use OpenID4VC\SIOPv2\Service\AuthorizationRequestValidator;
use OpenID4VC\SIOPv2\Service\AuthorizationResponseFactory;
use OpenID4VC\SIOPv2\Service\SelfIssuedIdTokenBuilder;
use OpenID4VC\SIOPv2\Subject\SubjectIdentifierInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class SelfIssuedOpenIdProvider
{
    public function __construct(
        private readonly AuthorizationRequestParser $requestParser = new AuthorizationRequestParser(),
        private readonly AuthorizationRequestValidator $requestValidator = new AuthorizationRequestValidator(),
        private readonly SelfIssuedIdTokenBuilder $idTokenBuilder = new SelfIssuedIdTokenBuilder(),
        private readonly AuthorizationResponseFactory $responseFactory = new AuthorizationResponseFactory(),
        private readonly LoggerInterface $logger = new NullLogger()
    ) {
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public function parseAuthorizationRequest(array $parameters): AuthorizationRequest
    {
        $this->logger->debug('Parsing authorization request.', [
            'parameter_count' => count($parameters),
        ]);

        return $this->requestParser->parse($parameters);
    }

    public function validateAuthorizationRequest(AuthorizationRequest $request): void
    {
        $this->requestValidator->validate($request);
    }

    /**
     * @param array<string, mixed> $additionalClaims
     * @param array<string, mixed> $additionalHeader
     * @param array<string, string> $additionalResponseParameters
     */
    public function createAuthorizationResponse(
        AuthorizationRequest $request,
        SubjectIdentifierInterface $subject,
        SignerInterface $signer,
        array $additionalClaims = [],
        array $additionalHeader = [],
        array $additionalResponseParameters = []
    ): AuthorizationResponse {
        $this->logger->info('Creating authorization response.', [
            'client_id' => $request->clientId,
            'subject' => $subject->subject(),
        ]);

        $idToken = $this->idTokenBuilder->build(
            request: $request,
            subject: $subject,
            signer: $signer,
            additionalClaims: $additionalClaims,
            additionalHeader: $additionalHeader
        );

        return $this->responseFactory->create($request, $idToken, $additionalResponseParameters);
    }
}
