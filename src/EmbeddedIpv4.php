<?php

declare(strict_types=1);

namespace Securized\Ssrf;

/**
 * IPv4 addresses a transition mechanism would forward an IPv6 address to.
 * NAT64 is unwrapped, never blacklisted: behind DNS64 every IPv4-only host resolves into it.
 */
readonly class EmbeddedIpv4
{
    private const NAT64_WELL_KNOWN_PREFIX = '64:ff9b::/96';

    private const IPV4_COMPATIBLE_PREFIX = "\0\0\0\0\0\0\0\0\0\0\0\0";

    private const IPV4_MAPPED_PREFIX = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

    private const IPV4_TRANSLATED_PREFIX = "\0\0\0\0\0\0\0\0\xff\xff\0\0";

    private const SIX_TO_FOUR_PREFIX = "\x20\x02";

    private const TEREDO_PREFIX = "\x20\x01\0\0";

    private const ISATAP_INTERFACE_IDS = ["\0\0\x5e\xfe", "\x02\0\x5e\xfe"];

    private const UNSPECIFIED_AND_LOOPBACK = ["\0\0\0\0", "\0\0\0\1"];

    /** @param  list<string>  $nat64Prefixes */
    public function __construct(
        private array $nat64Prefixes = [],
    ) {}

    /** @return list<string> */
    public function in(string $ip): array
    {
        $packed = $this->pack($ip);
        if ($packed === null) {
            return [];
        }

        $found = [];
        $prefix = substr($packed, 0, 12);
        $last = substr($packed, 12);

        if ($prefix === self::IPV4_COMPATIBLE_PREFIX && ! in_array($last, self::UNSPECIFIED_AND_LOOPBACK, true)) {
            $found[] = $last;
        }

        if (in_array($prefix, [self::IPV4_MAPPED_PREFIX, self::IPV4_TRANSLATED_PREFIX], true)) {
            $found[] = $last;
        }

        if (str_starts_with($packed, self::SIX_TO_FOUR_PREFIX)) {
            $found[] = substr($packed, 2, 4);
        }

        // Teredo carries its server, and its client with every bit inverted.
        if (str_starts_with($packed, self::TEREDO_PREFIX)) {
            $found[] = substr($packed, 4, 4);
            $found[] = $last ^ "\xff\xff\xff\xff";
        }

        if (in_array(substr($packed, 8, 4), self::ISATAP_INTERFACE_IDS, true)) {
            $found[] = $last;
        }

        return array_values(array_unique([
            ...array_map(fn (string $bytes): string => (string) inet_ntop($bytes), $found),
            ...$this->nat64($ip),
        ]));
    }

    /**
     * RFC 6052: the IPv4 address follows the prefix, skipping byte 8. A
     * gateway may ignore the bits after it, so only $wellFormed requires them zero.
     *
     * @return list<string>
     */
    public function nat64(string $ip, bool $wellFormed = false): array
    {
        $packed = $this->pack($ip);
        if ($packed === null) {
            return [];
        }

        $found = [];

        foreach (array_unique([self::NAT64_WELL_KNOWN_PREFIX, ...$this->nat64Prefixes]) as $prefix) {
            [$address, $length] = explode('/', $prefix);
            $start = intdiv((int) $length, 8);

            if (! str_starts_with($packed, substr((string) inet_pton($address), 0, $start))) {
                continue;
            }

            $ipv4 = $rest = '';
            for ($i = $start; $i < 16; $i++) {
                if ($i !== 8 && strlen($ipv4) < 4) {
                    $ipv4 .= $packed[$i];
                } else {
                    $rest .= $packed[$i];
                }
            }

            if (! $wellFormed || trim($rest, "\0") === '') {
                $found[] = (string) inet_ntop($ipv4);
            }
        }

        return $found;
    }

    private function pack(string $ip): ?string
    {
        $packed = @inet_pton($ip);

        return is_string($packed) && strlen($packed) === 16 ? $packed : null;
    }
}
