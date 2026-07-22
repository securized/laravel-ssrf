<?php

declare(strict_types=1);

namespace Securized\Ssrf;

use GuzzleHttp\Psr7\Uri;
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
    /** Default port per scheme, used when the URL omits an explicit port. */
    private const DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    private DnsResolver $dns;

    public function __construct(
        private SsrfOptions $options,
        ?DnsResolver $dns = null,
    ) {
        $this->dns = $dns ?? new NativeDnsResolver();
    }

    /**
     * @return array{url: string, host: string, ips: list<string>, pinned: bool}
     * @throws SsrfException
     */
    public function validate(string $url): array
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

        if (!$opts->sendCredentials && $uri->getUserInfo() !== '') {
            throw new InvalidUrlException('Credentials in URLs are not permitted.');
        }

        // Uri::getPort() returns null both when no port is given and when the
        // port equals the scheme default, so fall back to the default for the
        // scheme. Otherwise http://host:80 would skip port validation entirely.
        $port = $uri->getPort() ?? self::DEFAULT_PORTS[$scheme] ?? null;
        if ($port !== null) {
            $this->validatePort($port, $opts);
        }

        ['host' => $host, 'ips' => $ips] = $this->validateHost($host, $opts);

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
        return $this->validate($url)['url'];
    }

    private function validateScheme(string $scheme, SsrfOptions $opts): void
    {
        if ($opts->whitelistSchemes !== [] && !in_array($scheme, $opts->whitelistSchemes, true)) {
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
        if ($opts->whitelistPorts !== [] && !in_array($port, $opts->whitelistPorts, true)) {
            throw new InvalidPortException(
                sprintf('Port "%d" is not in the whitelist: %s', $port, implode(', ', $opts->whitelistPorts))
            );
        }

        if ($opts->blacklistPorts !== [] && in_array($port, $opts->blacklistPorts, true)) {
            throw new InvalidPortException(sprintf('Port "%d" is blacklisted.', $port));
        }
    }

    /** @return array{host: string, ips: list<string>} */
    private function validateHost(string $host, SsrfOptions $opts): array
    {
        $host = strtolower(trim($host, '[]'));

        if ($opts->whitelistDomains !== [] && !$this->matchesList($host, $opts->whitelistDomains)) {
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

        $this->validateIps($ips, $host, $opts);

        return ['host' => $host, 'ips' => $ips];
    }

    /** @param list<string> $ips */
    private function validateIps(array $ips, string $host, SsrfOptions $opts): void
    {
        $ips = collect($ips);

        if ($opts->whitelistIps !== []) {
            $whitelist = collect($opts->whitelistIps);
            $allowed = $ips->contains(fn (string $ip) =>
                $whitelist->contains(fn (string $range) => $this->cidrMatch($ip, $range))
            );

            if (!$allowed) {
                throw new InvalidIpException(
                    sprintf('Host "%s" resolves to [%s] which is not in the IP whitelist.', $host, $ips->implode(', '))
                );
            }
        }

        $ips->each(function (string $ip) use ($host, $opts): void {
            collect($opts->blacklistIps)->each(function (string $range) use ($ip, $host): void {
                if ($this->cidrMatch($ip, $range)) {
                    throw new InvalidIpException(
                        sprintf('Host "%s" resolves to "%s" which matches blacklisted range "%s".', $host, $ip, $range)
                    );
                }
            });
        });
    }

    /**
     * Match a host against a list of domain patterns.
     *
     * Patterns are treated as regular expressions (anchored, case-insensitive)
     * so that entries like `.*\.example\.com` work. A malformed pattern is a
     * configuration error and throws rather than silently failing to match —
     * a typo in a blacklist must never quietly allow a host through.
     *
     * @param list<string> $patterns
     * @throws InvalidDomainException
     */
    private function matchesList(string $host, array $patterns): bool
    {
        return collect($patterns)->contains(function (string $pattern) use ($host): bool {
            $regex = sprintf('/^%s$/i', $pattern);
            $error = null;

            set_error_handler(static function (int $_, string $message) use (&$error): bool {
                $error = $message;

                return true;
            });

            try {
                $matched = preg_match($regex, $host);
            } finally {
                restore_error_handler();
            }

            if ($matched === false) {
                throw new InvalidDomainException(sprintf(
                    'Domain pattern "%s" is not a valid regular expression%s',
                    $pattern,
                    $error === null ? '.' : sprintf(': %s', str_replace('preg_match(): ', '', $error)),
                ));
            }

            return $matched === 1;
        });
    }

    /** Wrap IPv6 addresses in brackets so they are valid inside a URL authority. */
    private function formatHost(string $ip): string
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? sprintf('[%s]', $ip) : $ip;
    }

    private function cidrMatch(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
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
        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = $prefixLen === 0 ? 0 : (-1 << (32 - $prefixLen));

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    private function ipv6Match(string $ip, string $subnet, int $prefixLen): bool
    {
        $ipBin     = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        $mask = str_repeat("\xff", intdiv($prefixLen, 8));
        if ($prefixLen % 8 > 0) {
            $mask .= chr(0xff << (8 - $prefixLen % 8) & 0xff);
        }
        $mask = str_pad($mask, 16, "\x00");

        return ($ipBin & $mask) === ($subnetBin & $mask);
    }
}
