<?php

declare(strict_types=1);

namespace Securized\Ssrf\Http\Middleware;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\Http\DnsPinner;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

class SsrfProtectionMiddleware
{
    public const REWRITE_OPTION = DnsPinner::REWRITE_OPTION;

    public function __construct(
        private readonly SsrfValidator $validator,
        private readonly DnsPinner $pinner = new DnsPinner,
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
                    [$request, $options] = $this->pinner->pin($request, $options, $result['host'], $result['ips']);
                }

                return $next($request, $options);
            };
        };
    }

    public static function make(?SsrfOptions $options = null): callable
    {
        return (new self(new SsrfValidator($options ?? new SsrfOptions)))->handler();
    }
}
