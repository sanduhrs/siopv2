<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Clock;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

final class FrozenClock implements ClockInterface
{
    public function __construct(
        private readonly DateTimeImmutable $now
    ) {
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }
}
