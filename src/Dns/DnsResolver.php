<?php

declare(strict_types=1);

namespace Securized\Ssrf\Dns;

interface DnsResolver
{
    /** @return list<string> */
    public function resolve(string $host): array;
}
