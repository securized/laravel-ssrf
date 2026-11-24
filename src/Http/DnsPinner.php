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
        $asciiHost = $this->asciiHost($host);
        $usesCurl = $this->usesCurl($options);
        $proxied = $this->mayUseProxy($options, $scheme, $usesCurl);

        // Once the URL carries the IP, no_proxy can no longer match the name,
        // so a host it exempts is sent direct explicitly.
        if ($proxied && $this->exemptFromProxy($options, $asciiHost ?? $host)) {
            $options['proxy'] = '';
            if ($usesCurl) {
                $options['curl'][CURLOPT_PROXY] = '';
            }
            $proxied = false;
        }

        // Proxied plain HTTP is rewritten too: connect-to would force CONNECT,
        // which proxies commonly refuse for port 80.
        if (! $usesCurl || $asciiHost === null || ($proxied && $scheme !== 'https')) {
            $authority = ($asciiHost ?? $host).($uri->getPort() === null ? '' : ':'.$uri->getPort());

            return [$request->withUri($uri->withHost($this->bracketIpv6($ips[0])))->withHeader('Host', $authority), $options];
        }

        // curl matches resolve and connect-to entries against the punycode
        // name, and before 7.82 against the name without its trailing dot.
        $curlHost = str_ends_with($asciiHost, '.') ? substr($asciiHost, 0, -1) : $asciiHost;
        if ($curlHost !== $host) {
            $request = $request->withUri($uri->withHost($curlHost));
        }

        $port = $uri->getPort() ?? self::DEFAULT_PORTS[$scheme] ?? 80;

        if ($proxied) {
            // A proxy resolves the name itself and never consults CURLOPT_RESOLVE.
            // curl uses the first matching connect-to entry, so ours goes first.
            $options['curl'][CURLOPT_CONNECT_TO] = [
                sprintf('%s:%d:%s:%d', $curlHost, $port, $this->bracketIpv6($ips[0]), $port),
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
                $curlHost,
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
        if ($usesCurl && ! empty($options['curl'][CURLOPT_PROXY])) {
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

    /** @param  array<string, mixed>  $options */
    private function exemptFromProxy(array $options, string $host): bool
    {
        $proxy = $options['proxy'] ?? null;
        $patterns = is_array($proxy) ? (array) ($proxy['no'] ?? []) : [];

        // libcurl applies these to any proxy, including one set explicitly.
        foreach (['no_proxy', 'NO_PROXY'] as $name) {
            $patterns = [...$patterns, ...explode(',', str_replace(' ', '', (string) getenv($name)))];
        }

        $patterns = array_values(array_filter($patterns, fn (mixed $pattern): bool => is_string($pattern) && $pattern !== ''));

        return $patterns !== [] && Utils::isHostInNoProxy($host, $patterns);
    }

    private function asciiHost(string $host): ?string
    {
        if (! preg_match('/[^\x00-\x7F]/', $host)) {
            return $host;
        }

        if (! function_exists('idn_to_ascii')) {
            return null;
        }

        $ascii = idn_to_ascii($host, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);

        return $ascii === false ? null : strtolower($ascii);
    }

    private function bracketIpv6(string $ip): string
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? sprintf('[%s]', $ip) : $ip;
    }
}
