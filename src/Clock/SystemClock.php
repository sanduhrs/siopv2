<?php

declare(strict_types=1);

namespace OpenID4VC\SIOPv2\Clock;

use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

final class SystemClock implements ClockInterface
{
    public function __construct(
        private readonly DateTimeZone $timeZone = new DateTimeZone('UTC')
    ) {
    }

    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', $this->timeZone);
    }
}
