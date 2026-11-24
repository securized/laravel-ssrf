<?php

declare(strict_types=1);

/**
 * Two regressions:
 *
 *  1. IPv6 addresses must be bracketed when substituted into a URL authority,
 *     otherwise "2606:4700::1111" parses as host "2606" port "4700".
 *  2. The Guzzle middleware must pin only when pinning is actually enabled.
 *     Gating on a URL string comparison also fires on incidental
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

/** The middleware marks its entries as expiring where libcurl supports it. */
function pinEntry(string $entry): string
{
    return SsrfProtectionMiddleware::expiringPrefix().$entry;
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

    test('middleware brackets a pinned IPv6 address in the CURLOPT_RESOLVE entry', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('v6.example.com', '2606:4700::1111');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('http://v6.example.com/path');

        expect($history[0]['options']['curl'][CURLOPT_RESOLVE])->toBe([pinEntry('v6.example.com:80:[2606:4700::1111]')]);
    });

    test('middleware brackets a pinned IPv6 host when falling back to a URL rewrite', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('v6.example.com', '2606:4700::1111');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('http://v6.example.com/path', ['stream' => true]);

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

        expect($history[0]['request']->getUri()->getHost())->not->toBe('93.184.216.34')
            ->and($history[0]['options'])->not->toHaveKey('curl');
    });

    test('an already-normalised URL is left untouched', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(), $dns, $history)->get('http://example.com/path');

        expect($history[0]['request']->getUri()->getHost())->toBe('example.com')
            ->and($history[0]['options'])->not->toHaveKey('curl');
    });
});

describe('middleware pins through CURLOPT_RESOLVE', function (): void {
    test('the URL keeps its hostname and curl is told which IP to connect to', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('https://example.com/path');

        expect((string) $history[0]['request']->getUri())->toBe('https://example.com/path')
            ->and($history[0]['request']->getHeaderLine('Host'))->toBe('example.com')
            ->and($history[0]['options']['curl'][CURLOPT_RESOLVE])->toBe([pinEntry('example.com:443:93.184.216.34')]);
    });

    test('the default port follows the scheme', function (string $url, string $entry): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get($url);

        expect($history[0]['options']['curl'][CURLOPT_RESOLVE])->toBe([pinEntry($entry)]);
    })->with([
        'http' => ['http://example.com/', 'example.com:80:93.184.216.34'],
        'https' => ['https://example.com/', 'example.com:443:93.184.216.34'],
        'explicit port' => ['http://example.com:8080/', 'example.com:8080:93.184.216.34'],
    ]);

    test('the hostname is lowercased to match what was validated', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('http://EXAMPLE.com/');

        expect($history[0]['options']['curl'][CURLOPT_RESOLVE])->toBe([pinEntry('example.com:80:93.184.216.34')]);
    });

    test('caller-supplied curl options are kept and the pin is appended last', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('http://example.com/', ['curl' => [
            CURLOPT_RESOLVE => ['example.com:80:10.0.0.1'],
            CURLOPT_TCP_NODELAY => true,
        ]]);

        expect($history[0]['options']['curl'][CURLOPT_TCP_NODELAY])->toBeTrue()
            ->and($history[0]['options']['curl'][CURLOPT_RESOLVE])
            ->toBe(['example.com:80:10.0.0.1', pinEntry('example.com:80:93.184.216.34')]);
    });

    test('an IP literal host needs no pinning', function (): void {
        $history = [];
        pinnedClient(unpinnedOpts(true), new FakeDnsResolver, $history)->get('http://93.184.216.34/');

        expect($history[0]['options'])->not->toHaveKey('curl');
    });

    test('with the stream handler the host is rewritten instead, as curl options would be ignored', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('http://example.com/path', ['stream' => true]);

        expect($history[0]['request']->getUri()->getHost())->toBe('93.184.216.34')
            ->and($history[0]['request']->getHeaderLine('Host'))->toBe('example.com')
            ->and($history[0]['options'])->not->toHaveKey('curl');
    });
});

describe('middleware pins every validated address', function (): void {
    test('all resolved IPs go into one entry so curl can fail over', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34', '2606:4700::1111');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('https://example.com/');

        expect($history[0]['options']['curl'][CURLOPT_RESOLVE])
            ->toBe([pinEntry('example.com:443:93.184.216.34,[2606:4700::1111]')]);
    });

    test('with an IP whitelist only the whitelisted addresses are pinned', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '8.8.8.8', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true)->withWhitelistIps(['93.184.216.34']), $dns, $history)->get('https://example.com/');

        expect($history[0]['options']['curl'][CURLOPT_RESOLVE])->toBe([pinEntry('example.com:443:93.184.216.34')]);
    });

    test('safeUrl substitutes a whitelisted address, not just the first one resolved', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '8.8.8.8', '93.184.216.34');
        $validator = new SsrfValidator(unpinnedOpts(true)->withWhitelistIps(['93.184.216.34']), $dns);

        expect($validator->safeUrl('https://example.com/path'))->toBe('https://93.184.216.34/path');
    });
});

describe('middleware pins IDN hosts', function (): void {
    test('the request and the entry both use the punycode name curl looks up', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('bücher.example', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('https://bücher.example/path');

        expect((string) $history[0]['request']->getUri())->toBe('https://xn--bcher-kva.example/path')
            ->and($history[0]['request']->getHeaderLine('Host'))->toBe('xn--bcher-kva.example')
            ->and($history[0]['options']['curl'][CURLOPT_RESOLVE])->toBe([pinEntry('xn--bcher-kva.example:443:93.184.216.34')]);
    })->skip(! function_exists('idn_to_ascii'), 'ext-intl is not installed');
});

describe('middleware pins through a proxy', function (): void {
    test('HTTPS tunnels to the validated IP via connect-to and keeps the hostname', function (array $options): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34', '93.184.216.35');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('https://example.com/path', $options);

        expect((string) $history[0]['request']->getUri())->toBe('https://example.com/path')
            ->and($history[0]['options']['curl'][CURLOPT_CONNECT_TO])->toBe(['example.com:443:93.184.216.34:443'])
            ->and($history[0]['options']['curl'])->not->toHaveKey(CURLOPT_RESOLVE);
    })->with([
        'proxy string' => [['proxy' => 'http://proxy.test:3128']],
        'proxy per scheme' => [['proxy' => ['https' => 'http://proxy.test:3128']]],
        'CURLOPT_PROXY' => [['curl' => [CURLOPT_PROXY => 'http://proxy.test:3128']]],
    ]);

    test('the pinned connect-to entry goes first, as curl uses the first match', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('https://example.com/', [
            'proxy' => 'http://proxy.test:3128',
            'curl' => [CURLOPT_CONNECT_TO => ['example.com:443:10.0.0.1:443']],
        ]);

        expect($history[0]['options']['curl'][CURLOPT_CONNECT_TO])
            ->toBe(['example.com:443:93.184.216.34:443', 'example.com:443:10.0.0.1:443']);
    });

    test('plain HTTP sends the validated IP to the proxy and keeps the Host header', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('http://example.com:8080/path', ['proxy' => 'http://proxy.test:3128']);

        expect((string) $history[0]['request']->getUri())->toBe('http://93.184.216.34:8080/path')
            ->and($history[0]['request']->getHeaderLine('Host'))->toBe('example.com:8080')
            ->and($history[0]['options'])->not->toHaveKey('curl');
    });

    test('a proxy configured for another scheme does not change how the request is pinned', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('https://example.com/', ['proxy' => ['http' => 'http://proxy.test:3128']]);

        expect($history[0]['options']['curl'])->toHaveKey(CURLOPT_RESOLVE)->not->toHaveKey(CURLOPT_CONNECT_TO);
    });

    test('an empty proxy string means no proxy, whatever the environment says', function (): void {
        putenv('https_proxy=http://proxy.test:3128');

        try {
            $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
            $history = [];
            pinnedClient(unpinnedOpts(true), $dns, $history)->get('https://example.com/', ['proxy' => '']);

            expect($history[0]['options']['curl'])->toHaveKey(CURLOPT_RESOLVE)->not->toHaveKey(CURLOPT_CONNECT_TO);
        } finally {
            putenv('https_proxy');
        }
    });

    test('a proxy from the environment is pinned through as well', function (): void {
        putenv('https_proxy=http://proxy.test:3128');

        try {
            $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
            $history = [];
            pinnedClient(unpinnedOpts(true), $dns, $history)->get('https://example.com/');

            expect($history[0]['options']['curl'][CURLOPT_CONNECT_TO])->toBe(['example.com:443:93.184.216.34:443']);
        } finally {
            putenv('https_proxy');
        }
    });
});

describe('middleware fallback to a URL rewrite', function (): void {
    test('the Host header keeps a non-default port', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $history = [];
        pinnedClient(unpinnedOpts(true), $dns, $history)->get('http://example.com:8080/path', ['stream' => true]);

        expect((string) $history[0]['request']->getUri())->toBe('http://93.184.216.34:8080/path')
            ->and($history[0]['request']->getHeaderLine('Host'))->toBe('example.com:8080');
    });
});
