<?php

declare(strict_types=1);

namespace Securized\Ssrf\Dns;

class NativeDnsResolver implements DnsResolver
{
    /** @return list<string> */
    public function resolve(string $host): array
    {
        $a = @dns_get_record($host, DNS_A) ?: [];
        $aaaa = @dns_get_record($host, DNS_AAAA) ?: [];

        $ips = collect($a)->pluck('ip')
            ->merge(collect($aaaa)->pluck('ipv6'))
            ->values()
            ->all();

        // Fallback: dns_get_record only asks DNS, while curl resolves through
        // libc, which also reads the hosts file. Catch those names so the
        // blacklist can reject them.
        if ($ips === []) {
            $resolved = @gethostbyname($host);
            if ($resolved !== $host && filter_var($resolved, FILTER_VALIDATE_IP)) {
                $ips = [$resolved];
            }
        }

        return $ips;
    }
}
