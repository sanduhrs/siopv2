<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Did;

use OpenID4VC\SIOPv2\Model\ResolvedDidDocument;

interface DidDocumentResolverInterface
{
    public function resolve(string $did, ?string $kid = null): ResolvedDidDocument;
}
