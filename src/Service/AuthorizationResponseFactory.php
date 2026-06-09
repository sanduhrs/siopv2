<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Service;

use OpenID4VC\SIOPv2\Model\AuthorizationRequest;
use OpenID4VC\SIOPv2\Model\AuthorizationResponse;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class AuthorizationResponseFactory
{
    public function __construct(
        private readonly LoggerInterface $logger = new NullLogger()
    ) {
    }

    /**
     * @param array<string, string> $additionalParameters
     */
    public function create(
        AuthorizationRequest $request,
        string $idToken,
        array $additionalParameters = []
    ): AuthorizationResponse {
        $parameters = array_merge(['id_token' => $idToken], $additionalParameters);
        if ($request->state !== null) {
            $parameters['state'] = $request->state;
        }

        $this->logger->info('Authorization response created.', [
            'redirect_uri' => $request->redirectUri,
            'has_state' => $request->state !== null,
        ]);

        return new AuthorizationResponse(
            redirectUri: $request->redirectUri,
            parameters: $parameters
        );
    }

    public function buildRedirectUri(AuthorizationResponse $response): string
    {
        $separator = str_contains($response->redirectUri, '#') ? '&' : '#';

        $this->logger->debug('Building authorization response redirect URI.', [
            'redirect_uri' => $response->redirectUri,
        ]);

        return $response->redirectUri . $separator . http_build_query($response->parameters);
    }
}
