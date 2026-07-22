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
                if ($result['pinned'] && $result['ips'] !== []) {
                    $request = $request
                        ->withUri($request->getUri()->withHost($this->pinnedHost($result['ips'][0])))
                        ->withHeader('Host', $result['host']);
                }

                return $next($request, $options);
            };
        };
    }

    /** IPv6 addresses must be bracketed to be valid inside a URL authority. */
    private function pinnedHost(string $ip): string
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? sprintf('[%s]', $ip) : $ip;
    }

    public static function make(?SsrfOptions $options = null): callable
    {
        return (new self(new SsrfValidator($options ?? new SsrfOptions)))->handler();
    }
}
