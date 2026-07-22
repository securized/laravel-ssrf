<?php

declare(strict_types=1);

/**
 * D2 DNS Pinning — host rewriting correctness.
 *
 * Two regressions are covered here:
 *
 *  1. IPv6 addresses must be bracketed when substituted into a URL authority,
 *     otherwise "2606:4700::1111" parses as host "2606" port "4700".
 *  2. The Guzzle middleware must rewrite the host only when pinning is actually
 *     enabled. Gating on a URL string comparison also fires on incidental
 *     normalisation (scheme/host case), silently pinning unpinned requests.
 */

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Http\Middleware\SsrfProtectionMiddleware;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function pinnedClient(SsrfOptions $opts, FakeDnsResolver $dns, array &$history = []): Client
{
    $stack = HandlerStack::create(new MockHandler([new Response(200)]));
    // Guzzle runs the last-pushed middleware first, so history must be pushed
    // after the SSRF middleware in order to observe its host rewriting.
    $stack->push((new SsrfProtectionMiddleware(new SsrfValidator($opts, $dns)))->handler());
    $stack->push(Middleware::history($history));

    return new Client(['handler' => $stack]);
}

function unpinnedOpts(bool $pin = false): SsrfOptions
{
    return (new SsrfOptions)->withBlacklistIps([])->withPinDns($pin);
}

describe('IPv6 pinning produces a valid URL', function (): void {
    test('pinned IPv6 host is bracketed', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('v6.example.com', '2606:4700::1111');
        $result = (new SsrfValidator(unpinnedOpts(true), $dns))->validate('http://v6.example.com/path');

        expect($result['url'])->toBe('http://[2606:4700::1111]/path');
    });

    test('the pinned IPv6 URL survives a parse round-trip with host and port intact', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('v6.example.com', '2606:4700::1111');
        $result = (new SsrfValidator(unpinnedOpts(true), $dns))->validate('http://v6.example.com:8080/path');
        $uri = new Uri($result['url']);

        expect($uri->getHost())->toBe('[2606:4700::1111]')
            ->and($uri->getPort())->toBe(8080);
    });

    test('pinned IPv4 host is not bracketed', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('v4.example.com', '93.184.216.34');
        $result = (new SsrfValidator(unpinnedOpts(true), $dns))->validate('http://v4.example.com/path');

        expect($result['url'])->toBe('http://93.184.216.34/path');
    });

    test('middleware brackets a pinned IPv6 host on the outgoing request', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('v6.example.com', '2606:4700::1111');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('http://v6.example.com/path');

        expect($history[0]['request']->getUri()->getHost())->toBe('[2606:4700::1111]');
    });
});

describe('validate() reports whether pinning was applied', function (): void {
    test('pinned flag is true when pin_dns is on', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');

        expect((new SsrfValidator(unpinnedOpts(true), $dns))->validate('http://example.com/')['pinned'])->toBeTrue();
    });

    test('pinned flag is false when pin_dns is off', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');

        expect((new SsrfValidator(unpinnedOpts(), $dns))->validate('http://example.com/')['pinned'])->toBeFalse();
    });
});

describe('middleware does not pin when pin_dns is disabled', function (): void {
    test('a URL needing normalisation is not silently pinned to its IP', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(), $dns, $history)->get('HTTP://EXAMPLE.COM/path');

        expect($history[0]['request']->getUri()->getHost())->not->toBe('93.184.216.34');
    });

    test('an already-normalised URL is left untouched', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(), $dns, $history)->get('http://example.com/path');

        expect($history[0]['request']->getUri()->getHost())->toBe('example.com');
    });

    test('the host is still rewritten when pin_dns is enabled', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('http://example.com/path');

        expect($history[0]['request']->getUri()->getHost())->toBe('93.184.216.34')
            ->and($history[0]['request']->getHeaderLine('Host'))->toBe('example.com');
    });
});
