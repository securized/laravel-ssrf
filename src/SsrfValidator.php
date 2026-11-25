<?php

declare(strict_types=1);

namespace Securized\Ssrf;

use GuzzleHttp\Psr7\Uri;
use Illuminate\Support\Str;
use Securized\Ssrf\Dns\DnsResolver;
use Securized\Ssrf\Dns\NativeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidDomainException;
use Securized\Ssrf\Exceptions\InvalidIpException;
use Securized\Ssrf\Exceptions\InvalidPortException;
use Securized\Ssrf\Exceptions\InvalidSchemeException;
use Securized\Ssrf\Exceptions\InvalidUrlException;
use Securized\Ssrf\Exceptions\SsrfException;

readonly class SsrfValidator
{
    private const DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    private DnsResolver $dns;

    public function __construct(
        private SsrfOptions $options,
        ?DnsResolver $dns = null,
    ) {
        $this->dns = $dns ?? new NativeDnsResolver;
    }

    /**
     * @param  bool  $pinned  true only when the caller connects to the returned IPs and nothing else
     * @return array{url: string, host: string, ips: list<string>, pinned: bool}
     *
     * @throws SsrfException
     */
    public function validate(string $url, bool $pinned = false): array
    {
        $opts = $this->options;

        if (trim($url) === '') {
            throw new InvalidUrlException('Provided URL cannot be empty.');
        }

        try {
            $uri = new Uri($url);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidUrlException(sprintf('Could not parse URL: "%s"', $url), 0, $e);
        }

        $scheme = strtolower($uri->getScheme() ?: 'http');
        $this->validateScheme($scheme, $opts);

        $host = $uri->getHost();
        if ($host === '') {
            throw new InvalidUrlException(sprintf('URL does not contain a hostname: "%s"', $url));
        }

        if (! $opts->sendCredentials && $uri->getUserInfo() !== '') {
            throw new InvalidUrlException('Credentials in URLs are not permitted.');
        }

        // Uri::getPort() returns null for a port equal to the scheme default,
        // not just for an absent one — without this, https://host/ would skip
        // port validation entirely.
        $port = $uri->getPort() ?? self::DEFAULT_PORTS[$scheme] ?? null;
        if ($port !== null) {
            $this->validatePort($port, $opts);
        }

        ['host' => $host, 'ips' => $ips] = $this->validateHost($host, $opts, $pinned && $opts->pinDns);

        $pinnedUri = $uri->withScheme($scheme);
        if ($opts->pinDns) {
            $pinnedUri = $pinnedUri->withHost($this->formatHost($ips[0]));
        }

        return ['url' => (string) $pinnedUri, 'host' => $host, 'ips' => $ips, 'pinned' => $opts->pinDns];
    }

    public function isSafe(string $url): bool
    {
        try {
            $this->validate($url);

            return true;
        } catch (SsrfException) {
            return false;
        }
    }

    public function safeUrl(string $url): string
    {
        return $this->validate($url, true)['url'];
    }

    private function validateScheme(string $scheme, SsrfOptions $opts): void
    {
        if ($opts->whitelistSchemes !== [] && ! in_array($scheme, $opts->whitelistSchemes, true)) {
            throw new InvalidSchemeException(
                sprintf('Scheme "%s" is not in the whitelist: %s', $scheme, implode(', ', $opts->whitelistSchemes))
            );
        }

        if ($opts->blacklistSchemes !== [] && in_array($scheme, $opts->blacklistSchemes, true)) {
            throw new InvalidSchemeException(sprintf('Scheme "%s" is blacklisted.', $scheme));
        }
    }

    private function validatePort(int $port, SsrfOptions $opts): void
    {
        if ($opts->whitelistPorts !== [] && ! in_array($port, $opts->whitelistPorts, true)) {
            throw new InvalidPortException(
                sprintf('Port "%d" is not in the whitelist: %s', $port, implode(', ', $opts->whitelistPorts))
            );
        }

        if ($opts->blacklistPorts !== [] && in_array($port, $opts->blacklistPorts, true)) {
            throw new InvalidPortException(sprintf('Port "%d" is blacklisted.', $port));
        }
    }

    /** @return array{host: string, ips: list<string>} */
    private function validateHost(string $host, SsrfOptions $opts, bool $pinned): array
    {
        $host = $this->normaliseHost($host);

        if ($this->isNonCanonicalIpv4($host)) {
            throw new InvalidUrlException(
                sprintf('Host "%s" is a numeric address that is not in dotted-decimal form.', $host)
            );
        }

        if ($opts->whitelistDomains !== [] && ! $this->matchesList($host, $opts->whitelistDomains)) {
            throw new InvalidDomainException(sprintf('Host "%s" is not in the domain whitelist.', $host));
        }

        if ($opts->blacklistDomains !== [] && $this->matchesList($host, $opts->blacklistDomains)) {
            throw new InvalidDomainException(sprintf('Host "%s" matches a blacklisted domain.', $host));
        }

        $ips = filter_var($host, FILTER_VALIDATE_IP)
            ? [$host]
            : $this->dns->resolve($host);

        if ($ips === []) {
            throw new InvalidDomainException(sprintf('Host "%s" does not resolve to any IP address.', $host));
        }

        return ['host' => $host, 'ips' => $this->validateIps($ips, $host, $opts, $pinned)];
    }

    /**
     * Returns the name curl will actually look up, so the lists, DNS and the
     * pin all see it: curl percent-decodes the host and maps IDN to punycode.
     */
    private function normaliseHost(string $host): string
    {
        if (str_starts_with($host, '[')) {
            $ip = trim($host, '[]');
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                throw new InvalidUrlException(sprintf('Host "%s" is not a valid IPv6 address.', $host));
            }

            return strtolower($ip);
        }

        $ascii = preg_match('/[^\x00-\x7F]/', $host) !== 1
            ? $host
            : (function_exists('idn_to_ascii') ? idn_to_ascii($host, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46) : false);

        $ascii = strtolower(is_string($ascii) && str_ends_with($ascii, '.') ? substr($ascii, 0, -1) : (string) $ascii);

        if (preg_match('/^[a-z0-9_][a-z0-9._-]*\z/', $ascii) !== 1) {
            throw new InvalidUrlException(sprintf('Host "%s" is not a valid hostname.', $host));
        }

        return $ascii;
    }

    /**
     * No TLD is all-numeric, so a host ending in a numeric label is an IPv4 address.
     * PHP, libc and curl read the non-canonical forms differently per build: reject, never interpret.
     */
    private function isNonCanonicalIpv4(string $host): bool
    {
        if (str_contains($host, ':')) {
            return false;
        }

        $labels = explode('.', $host);
        if (end($labels) === '') {
            array_pop($labels);
        }

        if (preg_match('/^(\d+|0x[0-9a-f]*)$/', (string) end($labels)) !== 1) {
            return false;
        }

        return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false;
    }

    /**
     * With an IP whitelist, returns only the whitelisted addresses, so pinning
     * cannot pick another address from the same DNS answer.
     *
     * @param  list<string>  $ips
     * @return non-empty-list<string>
     */
    private function validateIps(array $ips, string $host, SsrfOptions $opts, bool $pinned): array
    {
        $resolved = collect($ips);
        $allowed = $resolved;

        if ($opts->whitelistIps !== []) {
            $whitelist = collect($opts->whitelistIps);
            // Only NAT64 here: the other forms can sit in an address the attacker owns.
            $allowed = $resolved->filter(fn (string $ip) => collect([$ip, ...$this->nat64Ipv4($ip)])->contains(
                fn (string $candidate) => $whitelist->contains(fn (string $range) => $this->cidrMatch($candidate, $range))
            ))->values();

            // Unpinned, curl may connect to any address the name resolves to.
            if ($allowed->isEmpty() || (! $pinned && $allowed->count() !== $resolved->count())) {
                throw new InvalidIpException(
                    sprintf('Host "%s" resolves to [%s] which is not in the IP whitelist.', $host, $resolved->implode(', '))
                );
            }
        }

        foreach ($ips as $ip) {
            foreach ([$ip, ...$this->embeddedIpv4($ip)] as $candidate) {
                foreach ($opts->blacklistIps as $range) {
                    if ($this->cidrMatch($candidate, $range)) {
                        throw new InvalidIpException(sprintf(
                            'Host "%s" resolves to "%s"%s which matches blacklisted range "%s".',
                            $host, $ip, $candidate === $ip ? '' : sprintf(' (carrying %s)', $candidate), $range
                        ));
                    }
                }
            }
        }

        return $allowed->all();
    }

    /**
     * IPv4 addresses a transition mechanism would forward this address to.
     * NAT64 is unwrapped, never blacklisted: behind DNS64 every IPv4-only host resolves into it.
     *
     * @return list<string>
     */
    private function embeddedIpv4(string $ip): array
    {
        $packed = @inet_pton($ip);
        if (! is_string($packed) || strlen($packed) !== 16) {
            return [];
        }

        $found = [];
        $zeros = fn (int $bytes): string => str_repeat("\0", $bytes);

        // IPv4-compatible, IPv4-mapped and IPv4-translated.
        if (in_array(substr($packed, 0, 12), [$zeros(12), $zeros(10)."\xff\xff", $zeros(8)."\xff\xff\0\0"], true)) {
            $found[] = substr($packed, 12);
        }

        if (str_starts_with($packed, "\x20\x02")) {
            $found[] = substr($packed, 2, 4);
        }

        // Teredo carries its server, and its client with every bit inverted.
        if (str_starts_with($packed, "\x20\x01\0\0")) {
            $found[] = substr($packed, 4, 4);
            $found[] = substr($packed, 12) ^ "\xff\xff\xff\xff";
        }

        // ISATAP, in any prefix.
        if (in_array(substr($packed, 8, 4), ["\0\0\x5e\xfe", "\x02\0\x5e\xfe"], true)) {
            $found[] = substr($packed, 12);
        }

        return array_values(array_unique([
            ...array_map(fn (string $bytes): string => (string) inet_ntop($bytes), $found),
            ...$this->nat64Ipv4($ip),
        ]));
    }

    /**
     * RFC 6052: the IPv4 address follows the prefix, skipping byte 8.
     *
     * @return list<string>
     */
    private function nat64Ipv4(string $ip): array
    {
        $packed = @inet_pton($ip);
        $found = [];

        foreach (is_string($packed) && strlen($packed) === 16 ? $this->options->nat64Prefixes : [] as $prefix) {
            if ($this->cidrMatch($ip, $prefix)) {
                $bytes = '';
                for ($i = intdiv((int) explode('/', $prefix)[1], 8); strlen($bytes) < 4 && $i < 16; $i++) {
                    $bytes .= $i === 8 ? '' : $packed[$i];
                }
                $found[] = (string) inet_ntop(str_pad($bytes, 4, "\0"));
            }
        }

        return $found;

    }

    /**
     * Deliberately wildcard matching, not regex: a regex dot matches any
     * character, so `api.example.com` would also admit `apiXexample.com`.
     *
     * @param  list<string>  $patterns
     */
    private function matchesList(string $host, array $patterns): bool
    {
        return Str::is(array_map(strtolower(...), $patterns), $host);
    }

    /** IPv6 addresses must be bracketed to be valid inside a URL authority. */
    private function formatHost(string $ip): string
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? sprintf('[%s]', $ip) : $ip;
    }

    private function cidrMatch(string $ip, string $cidr): bool
    {
        if (! str_contains($cidr, '/')) {
            $packed = @inet_pton($ip);

            return $packed !== false && $packed === @inet_pton($cidr);
        }

        [$subnet, $prefix] = explode('/', $cidr, 2);
        $prefixLen = (int) $prefix;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->ipv4Match($ip, $subnet, $prefixLen);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->ipv6Match($ip, $subnet, $prefixLen);
        }

        return false;
    }

    private function ipv4Match(string $ip, string $subnet, int $prefixLen): bool
    {
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = $prefixLen === 0 ? 0 : (-1 << (32 - $prefixLen));

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    private function ipv6Match(string $ip, string $subnet, int $prefixLen): bool
    {
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        $mask = str_repeat("\xff", intdiv($prefixLen, 8));
        if ($prefixLen % 8 > 0) {
            $mask .= chr(0xFF << (8 - $prefixLen % 8) & 0xFF);
        }
        $mask = str_pad($mask, 16, "\x00");

        return ($ipBin & $mask) === ($subnetBin & $mask);
    }
}
