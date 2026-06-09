<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Service;

use OpenID4VC\SIOPv2\Clock\SystemClock;
use OpenID4VC\SIOPv2\Crypto\Jws;
use OpenID4VC\SIOPv2\Crypto\SignerInterface;
use OpenID4VC\SIOPv2\Model\AuthorizationRequest;
use OpenID4VC\SIOPv2\Subject\SubjectIdentifierInterface;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class SelfIssuedIdTokenBuilder
{
    public function __construct(
        private readonly ClockInterface $clock = new SystemClock(),
        private readonly int $lifetime = 300,
        private readonly LoggerInterface $logger = new NullLogger()
    ) {
    }

    /**
     * @param array<string, mixed> $additionalClaims
     * @param array<string, mixed> $additionalHeader
     */
    public function build(
        AuthorizationRequest $request,
        SubjectIdentifierInterface $subject,
        SignerInterface $signer,
        array $additionalClaims = [],
        array $additionalHeader = []
    ): string {
        $now = $this->clock->now()->getTimestamp();
        $payload = array_merge(
            [
                'iss' => $subject->subject(),
                'sub' => $subject->subject(),
                'aud' => $request->clientId,
                'nonce' => $request->nonce,
                'iat' => $now,
                'exp' => $now + $this->lifetime,
            ],
            $additionalClaims
        );

        if ($subject->publicKeyJwk() !== null && $subject->syntaxType() === 'urn:ietf:params:oauth:jwk-thumbprint') {
            $payload['sub_jwk'] = $subject->publicKeyJwk()->toArray();
        }

        $header = array_merge(
            [
                'typ' => 'JWT',
                'alg' => $signer->algorithm(),
            ],
            $additionalHeader
        );

        $this->logger->info('Building self-issued ID token.', [
            'subject' => $subject->subject(),
            'algorithm' => $signer->algorithm(),
            'audience' => $request->clientId,
        ]);

        return Jws::encode($header, $payload, $signer);
    }
}
