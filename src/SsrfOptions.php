<?php

declare(strict_types=1);

namespace Securized\Ssrf;

use InvalidArgumentException;

final class SsrfOptions
{
    private const DEFAULT_BLACKLIST_IPS = [
        // IPv4
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
        '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/29', '192.0.2.0/24',
        '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
        // IPv6
        '::/128',           // unspecified address
        '::1/128',          // loopback
        '::/96',            // IPv4-compatible (deprecated)
        '::ffff:0:0/96',    // IPv4-mapped IPv6 (blocks ::ffff:127.0.0.1, etc.)
        '::ffff:0:0:0/96',  // IPv4-translated (SIIT)
        '64:ff9b:1::/48',   // local-use NAT64 (RFC 8215)
        '100::/64',         // discard prefix (RFC 6666)
        '2001::/32',        // Teredo
        '2001:db8::/32',    // documentation range
        '2002::/16',        // 6to4 (can embed private IPv4: 2002:c0a8:0101:: = 192.168.1.1)
        'fc00::/7',         // unique local (includes fd00::/8)
        'fe80::/10',        // link-local
        'ff00::/8',         // multicast
    ];

    /**
     * @param  list<string>  $whitelistIps
     * @param  list<int>  $whitelistPorts
     * @param  list<string>  $whitelistDomains
     * @param  list<string>  $whitelistSchemes
     * @param  list<string>  $blacklistIps
     * @param  list<int>  $blacklistPorts
     * @param  list<string>  $blacklistDomains
     * @param  list<string>  $blacklistSchemes
     * @param  list<string>  $nat64Prefixes
     */
    public function __construct(
        public readonly bool $sendCredentials = false,
        public readonly bool $pinDns = false,
        public readonly array $whitelistIps = [],
        public readonly array $whitelistPorts = [80, 443, 8080],
        public readonly array $whitelistDomains = [],
        public readonly array $whitelistSchemes = ['http', 'https'],
        public readonly array $blacklistIps = self::DEFAULT_BLACKLIST_IPS,
        public readonly array $blacklistPorts = [],
        public readonly array $blacklistDomains = [],
        public readonly array $blacklistSchemes = [],
        public readonly array $nat64Prefixes = ['64:ff9b::/96'],
    ) {
        foreach ($nat64Prefixes as $prefix) {
            [$address, $length] = [...explode('/', $prefix, 2), ''];

            if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false || ! in_array($length, ['32', '40', '48', '56', '64', '96'], true)) {
                throw new InvalidArgumentException(sprintf('NAT64 prefix "%s" must be an IPv6 prefix of length 32, 40, 48, 56, 64 or 96 (RFC 6052).', $prefix));
            }
        }
    }

    /** @param array<string, mixed> $config */
    public static function fromConfig(array $config): self
    {
        return new self(
            sendCredentials: (bool) ($config['send_credentials'] ?? false),
            pinDns: (bool) ($config['pin_dns'] ?? false),
            whitelistIps: array_map('strval', $config['whitelist']['ips'] ?? []),
            whitelistPorts: array_map('intval', $config['whitelist']['ports'] ?? [80, 443, 8080]),
            whitelistDomains: array_map('strval', $config['whitelist']['domains'] ?? []),
            whitelistSchemes: array_map('strval', $config['whitelist']['schemes'] ?? ['http', 'https']),
            blacklistIps: array_map('strval', $config['blacklist']['ips'] ?? self::DEFAULT_BLACKLIST_IPS),
            blacklistPorts: array_map('intval', $config['blacklist']['ports'] ?? []),
            blacklistDomains: array_map('strval', $config['blacklist']['domains'] ?? []),
            blacklistSchemes: array_map('strval', $config['blacklist']['schemes'] ?? []),
            nat64Prefixes: array_map('strval', $config['nat64_prefixes'] ?? ['64:ff9b::/96']),
        );
    }

    public function withPinDns(bool $pin = true): self
    {
        return new self(...[...$this->all(), 'pinDns' => $pin]);
    }

    public function withSendCredentials(bool $allow = true): self
    {
        return new self(...[...$this->all(), 'sendCredentials' => $allow]);
    }

    /** @param list<string> $ips */
    public function withWhitelistIps(array $ips): self
    {
        return new self(...[...$this->all(), 'whitelistIps' => $ips]);
    }

    /** @param list<int> $ports */
    public function withWhitelistPorts(array $ports): self
    {
        return new self(...[...$this->all(), 'whitelistPorts' => $ports]);
    }

    /** @param list<string> $domains */
    public function withWhitelistDomains(array $domains): self
    {
        return new self(...[...$this->all(), 'whitelistDomains' => $domains]);
    }

    /** @param list<string> $schemes */
    public function withWhitelistSchemes(array $schemes): self
    {
        return new self(...[...$this->all(), 'whitelistSchemes' => $schemes]);
    }

    /** @param list<string> $ips */
    public function withBlacklistIps(array $ips): self
    {
        return new self(...[...$this->all(), 'blacklistIps' => $ips]);
    }

    /** @param list<int> $ports */
    public function withBlacklistPorts(array $ports): self
    {
        return new self(...[...$this->all(), 'blacklistPorts' => $ports]);
    }

    /** @param list<string> $domains */
    public function withBlacklistDomains(array $domains): self
    {
        return new self(...[...$this->all(), 'blacklistDomains' => $domains]);
    }

    /** @param list<string> $schemes */
    public function withBlacklistSchemes(array $schemes): self
    {
        return new self(...[...$this->all(), 'blacklistSchemes' => $schemes]);
    }

    /** @param list<string> $prefixes */
    public function withNat64Prefixes(array $prefixes): self
    {
        return new self(...[...$this->all(), 'nat64Prefixes' => $prefixes]);
    }

    public function addBlacklistIp(string ...$ips): self
    {
        return $this->withBlacklistIps(array_values(array_unique([...$this->blacklistIps, ...$ips])));
    }

    public function addBlacklistDomain(string ...$domains): self
    {
        return $this->withBlacklistDomains(array_values(array_unique([...$this->blacklistDomains, ...$domains])));
    }

    public function addWhitelistIp(string ...$ips): self
    {
        return $this->withWhitelistIps(array_values(array_unique([...$this->whitelistIps, ...$ips])));
    }

    public function addWhitelistDomain(string ...$domains): self
    {
        return $this->withWhitelistDomains(array_values(array_unique([...$this->whitelistDomains, ...$domains])));
    }

    /** @return array<string, mixed> */
    private function all(): array
    {
        return [
            'sendCredentials' => $this->sendCredentials,
            'pinDns' => $this->pinDns,
            'whitelistIps' => $this->whitelistIps,
            'whitelistPorts' => $this->whitelistPorts,
            'whitelistDomains' => $this->whitelistDomains,
            'whitelistSchemes' => $this->whitelistSchemes,
            'blacklistIps' => $this->blacklistIps,
            'blacklistPorts' => $this->blacklistPorts,
            'blacklistDomains' => $this->blacklistDomains,
            'blacklistSchemes' => $this->blacklistSchemes,
            'nat64Prefixes' => $this->nat64Prefixes,
        ];
    }
}
