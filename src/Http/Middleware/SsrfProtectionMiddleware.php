<?php

declare(strict_types=1);

namespace Securized\Ssrf\Http\Middleware;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

class SsrfProtectionMiddleware
{
    private const DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    public function __construct(
        private readonly SsrfValidator $validator,
    ) {}

    public function handler(): callable
    {
        return function (callable $next): callable {
            return function (RequestInterface $request, array $options) use ($next): PromiseInterface {
                $urlStr = (string) $request->getUri();

                try {
                    $result = $this->validator->validate($urlStr);
                } catch (SsrfException $e) {
                    return Create::rejectionFor(new RequestException($e->getMessage(), $request, null, $e));
                }

                // Gate on the pinned flag, never on a URL string comparison:
                // validate() also normalises case, so a string diff would pin
                // requests that never asked to be pinned.
                if ($result['pinned'] && ! filter_var($result['host'], FILTER_VALIDATE_IP)) {
                    [$request, $options] = $this->pin($request, $options, $result['host'], $result['ips']);
                }

                return $next($request, $options);
            };
        };
    }

    /**
     * Pins via CURLOPT_RESOLVE so the URL, Host header, SNI and certificate
     * check all keep the original hostname. Where curl would never consult
     * that entry (another handler, or a proxy doing the lookup), the pin is
     * applied another way instead of being silently dropped.
     *
     * @param  array<string, mixed>  $options
     * @param  non-empty-list<string>  $ips
     * @return array{RequestInterface, array<string, mixed>}
     */
    private function pin(RequestInterface $request, array $options, string $host, array $ips): array
    {
        $uri = $request->getUri();
        $scheme = strtolower($uri->getScheme());
        $proxied = $this->mayUseProxy($options, $scheme);
        $asciiHost = $this->asciiHost($host);

        // Substituting the IP into the URL costs nothing over plain HTTP, so a
        // proxied HTTP request takes this path too: connect-to would force the
        // proxy into CONNECT mode, which proxies commonly refuse for port 80.
        if (! $this->usesCurl($options) || $asciiHost === null || ($proxied && $scheme !== 'https')) {
            $authority = $uri->getPort() === null ? $host : $host.':'.$uri->getPort();

            return [$request->withUri($uri->withHost($this->bracketIpv6($ips[0])))->withHeader('Host', $authority), $options];
        }

        // curl matches these entries against the punycode name. Sending that
        // name ourselves avoids depending on curl's IDN conversion agreeing
        // with ours.
        if ($asciiHost !== $host) {
            $request = $request->withUri($uri->withHost($asciiHost));
        }

        $port = $uri->getPort() ?? self::DEFAULT_PORTS[$scheme] ?? 80;

        if ($proxied) {
            // A proxy resolves the name itself and never sees CURLOPT_RESOLVE.
            // connect-to has it tunnel to the validated IP while TLS keeps the
            // hostname. The first matching entry wins, so ours goes first.
            $options['curl'][CURLOPT_CONNECT_TO] = [
                sprintf('%s:%d:%s:%d', $asciiHost, $port, $this->bracketIpv6($ips[0]), $port),
                ...($options['curl'][CURLOPT_CONNECT_TO] ?? []),
            ];

            return [$request, $options];
        }

        // Appended last so it overrides any caller-supplied entry for this host:port.
        $options['curl'][CURLOPT_RESOLVE] = [
            ...($options['curl'][CURLOPT_RESOLVE] ?? []),
            sprintf(
                '%s%s:%d:%s',
                self::expiringPrefix(),
                $asciiHost,
                $port,
                implode(',', array_map($this->bracketIpv6(...), $ips)),
            ),
        ];

        return [$request, $options];
    }

    /**
     * Entries without a leading "+" never leave the DNS cache of a reused curl
     * handle, so a pin would outlive its request for as long as the worker
     * runs. libcurl before 7.75 reads the "+" as part of the hostname.
     */
    public static function expiringPrefix(): string
    {
        return (curl_version()['version_number'] ?? 0) >= 0x074B00 ? '+' : '';
    }

    /**
     * Mirrors how Guzzle picks a handler: the stream handler is only used for
     * `stream` requests when allow_url_fopen is on, or when curl is missing.
     *
     * @param  array<string, mixed>  $options
     */
    private function usesCurl(array $options): bool
    {
        if (! function_exists('curl_exec') && ! function_exists('curl_multi_exec')) {
            return false;
        }

        return empty($options['stream']) || ! ini_get('allow_url_fopen');
    }

    /**
     * Errs towards true: treating a direct request as proxied still pins it,
     * while missing a proxy would lose the pin. no_proxy lists are therefore
     * ignored.
     *
     * @param  array<string, mixed>  $options
     */
    private function mayUseProxy(array $options, string $scheme): bool
    {
        if (! empty($options['curl'][CURLOPT_PROXY])) {
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
        return array_any(
            [$scheme.'_proxy', strtoupper($scheme).'_PROXY', 'all_proxy', 'ALL_PROXY'],
            fn (string $name): bool => ! in_array(getenv($name), [false, ''], true),
        );
    }

    /** Null when the name is not ASCII and cannot be converted to punycode. */
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

    public static function make(?SsrfOptions $options = null): callable
    {
        return (new self(new SsrfValidator($options ?? new SsrfOptions)))->handler();
    }
}
