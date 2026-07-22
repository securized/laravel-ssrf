<?php

declare(strict_types=1);

namespace Securized\Ssrf\Dns;

class FakeDnsResolver implements DnsResolver
{
    /** @param array<string, list<string>> $records hostname → IPs */
    public function __construct(
        private array $records = [],
    ) {}

    public function addRecord(string $host, string ...$ips): self
    {
        $this->records[strtolower($host)] = $ips;

        return $this;
    }

    /** @return list<string> */
    public function resolve(string $host): array
    {
        return $this->records[strtolower($host)] ?? [];
    }
}
