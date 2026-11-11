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
                    [$request, $options] = $this->pin($request, $options, $result['host'], $result['ips'][0]);
                }

                return $next($request, $options);
            };
        };
    }

    /**
     * Pins via CURLOPT_RESOLVE so the URL, Host header, SNI and certificate
     * check all keep the original hostname. The stream handler ignores curl
     * options, so it falls back to substituting the IP into the URL instead.
     *
     * @param  array<string, mixed>  $options
     * @return array{RequestInterface, array<string, mixed>}
     */
    private function pin(RequestInterface $request, array $options, string $host, string $ip): array
    {
        $uri = $request->getUri();

        if (! empty($options['stream']) || ! function_exists('curl_exec')) {
            $request = $request->withUri($uri->withHost($this->bracketIpv6($ip)))->withHeader('Host', $host);

            return [$request, $options];
        }

        $port = $uri->getPort() ?? self::DEFAULT_PORTS[strtolower($uri->getScheme())] ?? 80;

        // Appended last so it overrides any caller-supplied entry for this host:port.
        $options['curl'][CURLOPT_RESOLVE] = [
            ...($options['curl'][CURLOPT_RESOLVE] ?? []),
            sprintf('%s:%d:%s', $host, $port, $this->bracketIpv6($ip)),
        ];

        return [$request, $options];
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
