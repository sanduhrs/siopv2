<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Service;

use OpenID4VC\SIOPv2\Clock\SystemClock;
use OpenID4VC\SIOPv2\Crypto\Jwk;
use OpenID4VC\SIOPv2\Crypto\JwkThumbprint;
use OpenID4VC\SIOPv2\Crypto\Jws;
use OpenID4VC\SIOPv2\Crypto\VerifierInterface;
use OpenID4VC\SIOPv2\Did\DidDocumentResolverInterface;
use OpenID4VC\SIOPv2\Exception\InvalidIdToken;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class SelfIssuedIdTokenValidator
{
    /**
     * @param list<string> $allowedAlgorithms
     */
    public function __construct(
        private readonly VerifierInterface $verifier,
        private readonly ?DidDocumentResolverInterface $didResolver = null,
        private readonly ClockInterface $clock = new SystemClock(),
        private readonly array $allowedAlgorithms = ['ES256'],
        private readonly int $clockSkew = 60,
        private readonly ?int $maxIssuedAtAge = 300,
        private readonly LoggerInterface $logger = new NullLogger()
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function validate(string $idToken, string $clientId, string $nonce): array
    {
        $decoded = Jws::decode($idToken);
        $payload = $decoded['payload'];
        $header = $decoded['header'];

        $iss = $payload['iss'] ?? null;
        $sub = $payload['sub'] ?? null;
        if (!is_string($iss) || !is_string($sub) || $iss !== $sub) {
            $this->logger->warning('Self-issued ID token rejected: iss/sub mismatch.');
            throw new InvalidIdToken('iss and sub must both be present and equal for a self-issued ID token.');
        }

        $audience = $payload['aud'] ?? null;
        if (is_string($audience)) {
            $audiences = [$audience];
        } elseif (is_array($audience)) {
            $audiences = array_values(array_filter($audience, 'is_string'));
        } else {
            $audiences = [];
        }

        if (!in_array($clientId, $audiences, true)) {
            $this->logger->warning('Self-issued ID token rejected: audience mismatch.', [
                'client_id' => $clientId,
            ]);
            throw new InvalidIdToken('aud does not contain the expected client_id.');
        }

        $tokenNonce = $payload['nonce'] ?? null;
        if (!is_string($tokenNonce) || $tokenNonce !== $nonce) {
            $this->logger->warning('Self-issued ID token rejected: nonce mismatch.');
            throw new InvalidIdToken('nonce does not match the authorization request.');
        }

        $algorithm = $header['alg'] ?? null;
        if (!is_string($algorithm) || !in_array($algorithm, $this->allowedAlgorithms, true)) {
            $this->logger->warning('Self-issued ID token rejected: unsupported algorithm.', [
                'algorithm' => $algorithm,
            ]);
            throw new InvalidIdToken('ID token uses an unsupported signing algorithm.');
        }

        $publicKey = $this->resolveVerificationKey($sub, $payload, $header);
        if (!$this->verifier->verify($idToken, $publicKey)) {
            $this->logger->warning('Self-issued ID token rejected: signature verification failed.', [
                'subject' => $sub,
            ]);
            throw new InvalidIdToken('ID token signature verification failed.');
        }

        $this->validateLifetime($payload);

        $this->logger->info('Self-issued ID token validated.', [
            'subject' => $sub,
            'algorithm' => $algorithm,
            'client_id' => $clientId,
        ]);

        return $payload;
    }

    /**
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $header
     */
    private function resolveVerificationKey(string $sub, array $payload, array $header): Jwk
    {
        if (str_starts_with($sub, 'did:')) {
            if ($this->didResolver === null) {
                $this->logger->warning('Self-issued ID token rejected: DID subject without resolver.', [
                    'subject' => $sub,
                ]);
                throw new InvalidIdToken('A DID subject requires a DID document resolver.');
            }

            $kid = isset($header['kid']) && is_string($header['kid']) ? $header['kid'] : null;
            $resolved = $this->didResolver->resolve($sub, $kid);
            if ($resolved->id !== $sub) {
                $this->logger->warning('Self-issued ID token rejected: DID resolver returned mismatched subject.', [
                    'subject' => $sub,
                ]);
                throw new InvalidIdToken('Resolved DID document does not match the token subject.');
            }

            return $resolved->publicKeyJwk;
        }

        $subJwkData = $payload['sub_jwk'] ?? null;
        if (!is_array($subJwkData)) {
            $this->logger->warning('Self-issued ID token rejected: missing sub_jwk for thumbprint subject.', [
                'subject' => $sub,
            ]);
            throw new InvalidIdToken('JWK thumbprint subject syntax requires a sub_jwk claim.');
        }

        $subJwk = Jwk::fromArray($this->assertStringKeyedMap($subJwkData));
        if (JwkThumbprint::thumbprint($subJwk) !== $sub) {
            $this->logger->warning('Self-issued ID token rejected: sub_jwk thumbprint mismatch.', [
                'subject' => $sub,
            ]);
            throw new InvalidIdToken('sub does not match the sub_jwk thumbprint.');
        }

        return $subJwk;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function validateLifetime(array $payload): void
    {
        $now = $this->clock->now()->getTimestamp();

        $exp = $payload['exp'] ?? null;
        if (!is_int($exp) || $exp < ($now - $this->clockSkew)) {
            $this->logger->warning('Self-issued ID token rejected: token expired.');
            throw new InvalidIdToken('ID token is expired.');
        }

        $iat = $payload['iat'] ?? null;
        if (!is_int($iat)) {
            $this->logger->warning('Self-issued ID token rejected: missing iat.');
            throw new InvalidIdToken('iat must be present.');
        }

        if ($iat > ($now + $this->clockSkew)) {
            $this->logger->warning('Self-issued ID token rejected: iat in future.');
            throw new InvalidIdToken('iat is in the future.');
        }

        if ($this->maxIssuedAtAge !== null && $iat < ($now - $this->maxIssuedAtAge - $this->clockSkew)) {
            $this->logger->warning('Self-issued ID token rejected: iat too old.');
            throw new InvalidIdToken('iat is older than the configured age limit.');
        }
    }

    /**
     * @param array<mixed, mixed> $value
     * @return array<string, mixed>
     */
    private function assertStringKeyedMap(array $value): array
    {
        foreach (array_keys($value) as $key) {
            if (!is_string($key)) {
                throw new InvalidIdToken('sub_jwk must be a JSON object with string keys.');
            }
        }

        /** @var array<string, mixed> $value */
        return $value;
    }
}
