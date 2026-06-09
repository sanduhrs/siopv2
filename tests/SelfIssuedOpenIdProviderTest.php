<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Tests;

use DateTimeImmutable;
use OpenID4VC\SIOPv2\Clock\FrozenClock;
use OpenID4VC\SIOPv2\Crypto\Jwk;
use OpenID4VC\SIOPv2\Crypto\OpenSslSigner;
use OpenID4VC\SIOPv2\Crypto\OpenSslVerifier;
use OpenID4VC\SIOPv2\Did\DidDocumentResolverInterface;
use OpenID4VC\SIOPv2\Model\ResolvedDidDocument;
use OpenID4VC\SIOPv2\SelfIssuedOpenIdProvider;
use OpenID4VC\SIOPv2\Service\AuthorizationResponseFactory;
use OpenID4VC\SIOPv2\Service\SelfIssuedIdTokenBuilder;
use OpenID4VC\SIOPv2\Service\SelfIssuedIdTokenValidator;
use OpenID4VC\SIOPv2\Subject\DidSubjectIdentifier;
use OpenID4VC\SIOPv2\Subject\JwkThumbprintSubjectIdentifier;
use Psr\Log\AbstractLogger;
use PHPUnit\Framework\TestCase;

final class SelfIssuedOpenIdProviderTest extends TestCase
{
    public function testCreatesAndValidatesJwkThumbprintAuthorizationResponse(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2026-04-16T12:00:00+00:00'));
        $provider = new SelfIssuedOpenIdProvider(
            idTokenBuilder: new SelfIssuedIdTokenBuilder($clock, 300)
        );

        $request = $provider->parseAuthorizationRequest([
            'client_id' => 'https://rp.example.com/callback',
            'redirect_uri' => 'https://rp.example.com/callback',
            'response_type' => 'id_token',
            'scope' => 'openid profile',
            'nonce' => 'nonce-123',
            'state' => 'state-456',
            'client_metadata' => json_encode([
                'subject_syntax_types_supported' => ['urn:ietf:params:oauth:jwk-thumbprint'],
                'id_token_signing_alg_values_supported' => ['ES256'],
            ], JSON_THROW_ON_ERROR),
        ]);

        $provider->validateAuthorizationRequest($request);

        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);

        self::assertNotFalse($privateKey);

        $publicJwk = $this->publicEcJwkFromPrivateKey($privateKey);
        $subject = new JwkThumbprintSubjectIdentifier($publicJwk);
        $signer = new OpenSslSigner($privateKey, 'ES256');

        $response = $provider->createAuthorizationResponse($request, $subject, $signer);
        $redirectUri = (new AuthorizationResponseFactory())->buildRedirectUri($response);

        self::assertStringContainsString('#id_token=', $redirectUri);
        self::assertStringContainsString('state=state-456', $redirectUri);

        $validator = new SelfIssuedIdTokenValidator(
            verifier: new OpenSslVerifier(),
            clock: $clock,
            allowedAlgorithms: ['ES256']
        );

        $payload = $validator->validate($response->parameters['id_token'], $request->clientId, $request->nonce);

        self::assertSame($payload['iss'], $payload['sub']);
        self::assertArrayHasKey('sub_jwk', $payload);
    }

    public function testValidatesDidSubjectUsingResolver(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2026-04-16T12:00:00+00:00'));
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);

        self::assertNotFalse($privateKey);

        $publicJwk = $this->publicEcJwkFromPrivateKey($privateKey);
        $subject = new DidSubjectIdentifier('did:example:holder-123');
        $signer = new OpenSslSigner($privateKey, 'ES256');

        $request = (new SelfIssuedOpenIdProvider(
            idTokenBuilder: new SelfIssuedIdTokenBuilder($clock, 300)
        ))->parseAuthorizationRequest([
            'client_id' => 'https://rp.example.com/callback',
            'redirect_uri' => 'https://rp.example.com/callback',
            'response_type' => 'id_token',
            'scope' => 'openid',
            'nonce' => 'nonce-did',
        ]);

        $idToken = (new SelfIssuedIdTokenBuilder($clock, 300))->build(
            request: $request,
            subject: $subject,
            signer: $signer,
            additionalHeader: ['kid' => 'did:example:holder-123#key-1']
        );

        $validator = new SelfIssuedIdTokenValidator(
            verifier: new OpenSslVerifier(),
            didResolver: new class ($publicJwk) implements DidDocumentResolverInterface {
                public function __construct(private readonly Jwk $publicJwk)
                {
                }

                public function resolve(string $did, ?string $kid = null): ResolvedDidDocument
                {
                    TestCase::assertSame('did:example:holder-123', $did);
                    TestCase::assertSame('did:example:holder-123#key-1', $kid);

                    return new ResolvedDidDocument($did, $this->publicJwk);
                }
            },
            clock: $clock,
            allowedAlgorithms: ['ES256']
        );

        $payload = $validator->validate($idToken, $request->clientId, $request->nonce);

        self::assertSame('did:example:holder-123', $payload['sub']);
        self::assertArrayNotHasKey('sub_jwk', $payload);
    }

    public function testLogsValidationAndTokenProcessingEvents(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2026-04-16T12:00:00+00:00'));
        $logger = new class () extends AbstractLogger {
            /** @var list<array{level: string, message: string, context: array<string, mixed>}> */
            public array $records = [];

            /**
             * @param mixed $level
             * @param string|\Stringable $message
             * @param array<string, mixed> $context
             */
            public function log($level, \Stringable|string $message, array $context = []): void
            {
                if (!is_string($level)) {
                    throw new \InvalidArgumentException('Log level must be a string.');
                }

                $this->records[] = [
                    'level' => $level,
                    'message' => (string) $message,
                    'context' => $context,
                ];
            }
        };

        $provider = new SelfIssuedOpenIdProvider(
            requestValidator: new \OpenID4VC\SIOPv2\Service\AuthorizationRequestValidator(
                logger: $logger
            ),
            idTokenBuilder: new SelfIssuedIdTokenBuilder($clock, 300, $logger),
            responseFactory: new AuthorizationResponseFactory($logger),
            logger: $logger
        );

        $request = $provider->parseAuthorizationRequest([
            'client_id' => 'https://rp.example.com/callback',
            'redirect_uri' => 'https://rp.example.com/callback',
            'response_type' => 'id_token',
            'scope' => 'openid',
            'nonce' => 'nonce-log',
        ]);
        $provider->validateAuthorizationRequest($request);

        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $privateKey);

        $subject = new JwkThumbprintSubjectIdentifier($this->publicEcJwkFromPrivateKey($privateKey));
        $response = $provider->createAuthorizationResponse(
            $request,
            $subject,
            new OpenSslSigner($privateKey, 'ES256')
        );

        $validator = new SelfIssuedIdTokenValidator(
            verifier: new OpenSslVerifier(),
            clock: $clock,
            allowedAlgorithms: ['ES256'],
            logger: $logger
        );
        $validator->validate($response->parameters['id_token'], $request->clientId, $request->nonce);

        self::assertNotEmpty($logger->records);
        self::assertContains(
            'Authorization request validated.',
            array_column($logger->records, 'message')
        );
        self::assertContains(
            'Self-issued ID token validated.',
            array_column($logger->records, 'message')
        );
    }

    private function publicEcJwkFromPrivateKey(\OpenSSLAsymmetricKey $privateKey): Jwk
    {
        $details = openssl_pkey_get_details($privateKey);

        self::assertIsArray($details);
        self::assertArrayHasKey('ec', $details);
        self::assertIsArray($details['ec']);
        self::assertArrayHasKey('x', $details['ec']);
        self::assertArrayHasKey('y', $details['ec']);
        self::assertIsString($details['ec']['x']);
        self::assertIsString($details['ec']['y']);

        $x = $details['ec']['x'];
        $y = $details['ec']['y'];

        return Jwk::fromArray([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => rtrim(strtr(base64_encode($x), '+/', '-_'), '='),
            'y' => rtrim(strtr(base64_encode($y), '+/', '-_'), '='),
        ]);
    }
}
