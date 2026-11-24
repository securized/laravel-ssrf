<?php

declare(strict_types=1);

namespace Securized\Ssrf\Http;

use GuzzleHttp\Utils;
use Psr\Http\Message\RequestInterface;

class DnsPinner
{
    /** Guzzle request option: pin by replacing the URL host, for clients using a handler that ignores curl options. */
    public const REWRITE_OPTION = 'ssrf_pin_rewrite';

    private const DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    /**
     * Pins via CURLOPT_RESOLVE so the URL, Host header, SNI and certificate
     * check all keep the original hostname.
     *
     * @param  array<string, mixed>  $options
     * @param  non-empty-list<string>  $ips
     * @return array{RequestInterface, array<string, mixed>}
     */
    public function pin(RequestInterface $request, array $options, string $host, array $ips): array
    {
        $uri = $request->getUri();
        $scheme = strtolower($uri->getScheme());
        $usesCurl = $this->usesCurl($options);
        $proxied = $this->mayUseProxy($options, $scheme, $usesCurl);

        // Once the URL carries the IP, no_proxy can no longer match the name,
        // so a host it exempts is sent direct explicitly.
        if ($proxied && $this->exemptFromProxy($options, $scheme, $host, $usesCurl)) {
            $options['proxy'] = '';
            if ($usesCurl) {
                $options['curl'][CURLOPT_PROXY] = '';
            }
            $proxied = false;
        }

        // Proxied plain HTTP is rewritten too: connect-to would force CONNECT,
        // which proxies commonly refuse for port 80.
        if (! $usesCurl || ($proxied && $scheme !== 'https')) {
            $authority = $host.($uri->getPort() === null ? '' : ':'.$uri->getPort());

            return [$request->withUri($uri->withHost($this->bracketIpv6($ips[0])))->withHeader('Host', $authority), $options];
        }

        // curl matches resolve and connect-to entries against the punycode
        // name, and before 7.82 against the name without its trailing dot.
        if ($uri->getHost() !== $host) {
            $request = $request->withUri($uri->withHost($host));
        }

        $port = $uri->getPort() ?? self::DEFAULT_PORTS[$scheme] ?? 80;

        if ($proxied) {
            // A proxy resolves the name itself and never consults CURLOPT_RESOLVE.
            // curl uses the first matching connect-to entry, so ours goes first.
            $options['curl'][CURLOPT_CONNECT_TO] = [
                sprintf('%s:%d:%s:%d', $host, $port, $this->bracketIpv6($ips[0]), $port),
                ...($options['curl'][CURLOPT_CONNECT_TO] ?? []),
            ];

            return [$request, $options];
        }

        // An expiring entry is stale at once when the DNS cache timeout is 0,
        // and curl would then resolve the name itself.
        $cacheDisabled = isset($options['curl'][CURLOPT_DNS_CACHE_TIMEOUT])
            && (int) $options['curl'][CURLOPT_DNS_CACHE_TIMEOUT] === 0;

        // Appended last so it overrides any caller-supplied entry for this host:port.
        $options['curl'][CURLOPT_RESOLVE] = [
            ...($options['curl'][CURLOPT_RESOLVE] ?? []),
            sprintf(
                '%s%s:%d:%s',
                $cacheDisabled ? '' : self::expiringPrefix(),
                $host,
                $port,
                implode(',', array_map($this->bracketIpv6(...), $ips)),
            ),
        ];

        return [$request, $options];
    }

    /**
     * Without "+" an entry never leaves a reused handle's DNS cache.
     * libcurl before 7.75 reads the "+" as part of the hostname.
     */
    public static function expiringPrefix(): string
    {
        return (curl_version()['version_number'] ?? 0) >= 0x074B00 ? '+' : '';
    }

    /**
     * Mirrors GuzzleHttp\Utils::chooseHandler(). A handler passed to the
     * client cannot be seen from here, hence the opt-out.
     *
     * @param  array<string, mixed>  $options
     */
    private function usesCurl(array $options): bool
    {
        if (! empty($options[self::REWRITE_OPTION])) {
            return false;
        }

        if (! function_exists('curl_exec') && ! function_exists('curl_multi_exec')) {
            return false;
        }

        return empty($options['stream']) || ! ini_get('allow_url_fopen');
    }

    /**
     * Errs towards true: a direct request treated as proxied is still pinned,
     * a missed proxy is not.
     *
     * @param  array<string, mixed>  $options
     */
    private function mayUseProxy(array $options, string $scheme, bool $usesCurl): bool
    {
        if ($usesCurl && (! empty($options['curl'][CURLOPT_PROXY]) || ! empty($options['curl'][CURLOPT_PRE_PROXY]))) {
            return true;
        }

        $proxy = $options['proxy'] ?? null;

        // An explicit string, even an empty one, stops curl reading the environment.
        if (is_string($proxy)) {
            return $proxy !== '';
        }

        if (is_array($proxy) && ! empty($proxy[$scheme])) {
            return true;
        }

        // libcurl reads these itself when it is not handed a proxy.
        return $usesCurl && array_any(
            [$scheme.'_proxy', strtoupper($scheme).'_PROXY', 'all_proxy', 'ALL_PROXY'],
            fn (string $name): bool => ! in_array(getenv($name), [false, ''], true),
        );
    }

    /**
     * Guzzle applies the `no` list only to its own proxy option; libcurl
     * applies the environment list to any proxy it is handed.
     *
     * @param  array<string, mixed>  $options
     */
    private function exemptFromProxy(array $options, string $scheme, string $host, bool $usesCurl): bool
    {
        $proxy = $options['proxy'] ?? null;
        $curlProxy = $usesCurl && (! empty($options['curl'][CURLOPT_PROXY]) || ! empty($options['curl'][CURLOPT_PRE_PROXY]));
        $patterns = ! $curlProxy && is_array($proxy) && ! empty($proxy[$scheme]) ? (array) ($proxy['no'] ?? []) : [];

        if ($usesCurl) {
            $patterns = [...$patterns, ...explode(',', (string) getenv('no_proxy')), ...explode(',', (string) getenv('NO_PROXY'))];
        }

        $patterns = array_values(array_filter(array_map(fn (mixed $pattern): string => strtolower(trim((string) $pattern)), $patterns)));

        return $patterns !== [] && Utils::isHostInNoProxy($host, $patterns);
    }

    private function bracketIpv6(string $ip): string
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? sprintf('[%s]', $ip) : $ip;
    }
}
