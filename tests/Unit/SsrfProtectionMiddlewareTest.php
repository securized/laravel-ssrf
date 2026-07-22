<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Securized\Ssrf\Http\Middleware\SsrfProtectionMiddleware;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a Guzzle client with the SSRF middleware and a mock handler.
 * Captured requests are stored in $history for inspection.
 */
function makeClient(SsrfOptions $opts, array &$history = [], array $responses = []): Client
{
    if (empty($responses)) {
        $responses = [new Response(200)];
    }

    $mock  = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));
    $stack->push(
        (new SsrfProtectionMiddleware(new SsrfValidator($opts)))->handler()
    );

    return new Client(['handler' => $stack]);
}

// ---------------------------------------------------------------------------
// Blocking behaviour
// ---------------------------------------------------------------------------

describe('SsrfProtectionMiddleware — blocking', function (): void {
    test('blocks request to localhost IP (127.0.0.1)', function (): void {
        $opts   = (new SsrfOptions())->withWhitelistDomains([]);
        $client = makeClient($opts);
        expect(fn () => $client->get('http://127.0.0.1/'))->toThrow(RequestException::class);
    });

    test('blocks request with disallowed scheme (file://)', function (): void {
        $client = makeClient(new SsrfOptions());
        expect(fn () => $client->get('file:///etc/passwd'))->toThrow(RequestException::class);
    });

    test('blocks request to disallowed port', function (): void {
        // Port 22 not in default whitelist [80, 443, 8080]
        $opts   = (new SsrfOptions())->withWhitelistDomains([]);
        $client = makeClient($opts);
        expect(fn () => $client->get('http://1.2.3.4:22/'))->toThrow(RequestException::class);
    });

    test('blocks request to RFC-1918 range (10.x.x.x)', function (): void {
        $opts   = (new SsrfOptions())->withWhitelistDomains([]);
        $client = makeClient($opts);
        expect(fn () => $client->get('http://10.0.0.1/'))->toThrow(RequestException::class);
    });

    test('blocks cloud metadata endpoint (169.254.169.254)', function (): void {
        $opts   = (new SsrfOptions())->withWhitelistDomains([]);
        $client = makeClient($opts);
        expect(fn () => $client->get('http://169.254.169.254/latest/meta-data/'))->toThrow(RequestException::class);
    });

    test('rejected promise wraps original SsrfException as cause', function (): void {
        $opts   = (new SsrfOptions())->withWhitelistDomains([]);
        $client = makeClient($opts);

        try {
            $client->get('http://127.0.0.1/');
            expect(false)->toBeTrue('Should have thrown');
        } catch (RequestException $e) {
            expect($e->getPrevious())->toBeInstanceOf(\Securized\Ssrf\Exceptions\SsrfException::class);
        }
    });
});

// ---------------------------------------------------------------------------
// Passing behaviour
// ---------------------------------------------------------------------------

describe('SsrfProtectionMiddleware — passing', function (): void {
    test('allows request to whitelisted public IP', function (): void {
        $opts = (new SsrfOptions())
            ->withWhitelistDomains([])
            ->withWhitelistSchemes([])
            ->withWhitelistPorts([])
            ->withBlacklistIps([])
            ->withWhitelistIps(['1.2.3.4']);

        $history   = [];
        $client    = makeClient($opts, $history);
        $response  = $client->get('http://1.2.3.4/path');

        expect($response->getStatusCode())->toBe(200);
        expect($history)->toHaveCount(1);
    });
});

// ---------------------------------------------------------------------------
// DNS pinning — URL rewrite
// ---------------------------------------------------------------------------

describe('SsrfProtectionMiddleware — DNS pinning', function (): void {
    test('with pin_dns, request URI host is replaced with IP and Host header is set', function (): void {
        $opts = (new SsrfOptions())
            ->withWhitelistDomains([])
            ->withWhitelistSchemes([])
            ->withWhitelistPorts([])
            ->withBlacklistIps([])
            ->withWhitelistIps(['1.2.3.4'])
            ->withPinDns();

        $history  = [];
        $client   = makeClient($opts, $history);
        $client->get('http://1.2.3.4/');

        $sentRequest = $history[0]['request'];

        // Host in URI should be the IP (same as hostname for a literal IP)
        expect((string) $sentRequest->getUri()->getHost())->toBe('1.2.3.4');
        // Host header preserved
        expect($sentRequest->hasHeader('Host'))->toBeTrue();
        expect($sentRequest->getHeaderLine('Host'))->toBe('1.2.3.4');
    });

    test('without pin_dns, request URI is unchanged', function (): void {
        $opts = (new SsrfOptions())
            ->withWhitelistDomains([])
            ->withWhitelistSchemes([])
            ->withWhitelistPorts([])
            ->withBlacklistIps([])
            ->withWhitelistIps(['1.2.3.4']);

        $history = [];
        $client  = makeClient($opts, $history);
        $client->get('http://1.2.3.4/path?q=1');

        $sentRequest = $history[0]['request'];
        expect((string) $sentRequest->getUri())->toBe('http://1.2.3.4/path?q=1');
    });
});

// ---------------------------------------------------------------------------
// Static factory SsrfProtectionMiddleware::make()
// ---------------------------------------------------------------------------

describe('SsrfProtectionMiddleware::make()', function (): void {
    test('make() with no arguments uses default SsrfOptions', function (): void {
        $middleware = SsrfProtectionMiddleware::make();
        expect($middleware)->toBeCallable();
    });

    test('make() with custom options blocks accordingly', function (): void {
        $opts  = (new SsrfOptions())
            ->withWhitelistSchemes(['https']) // blocks http
            ->withWhitelistDomains([]);

        $mock  = new MockHandler([new Response(200)]);
        $stack = HandlerStack::create($mock);
        $stack->push(SsrfProtectionMiddleware::make($opts));
        $client = new Client(['handler' => $stack]);

        expect(fn () => $client->get('http://1.2.3.4/'))->toThrow(RequestException::class);
    });

    test('make() with null options uses defaults and blocks localhost', function (): void {
        $mock  = new MockHandler([new Response(200)]);
        $stack = HandlerStack::create($mock);
        $stack->push(SsrfProtectionMiddleware::make(null));
        $client = new Client(['handler' => $stack]);

        expect(fn () => $client->get('http://127.0.0.1/'))->toThrow(RequestException::class);
    });
});

// ---------------------------------------------------------------------------
// Middleware respects validator options
// ---------------------------------------------------------------------------

describe('SsrfProtectionMiddleware — validator options', function (): void {
    test('middleware blocks based on validator options', function (): void {
        $opts = (new SsrfOptions())
            ->withWhitelistSchemes(['https'])
            ->withWhitelistDomains([])
            ->withWhitelistPorts([])
            ->withBlacklistIps([]);

        $middleware = new SsrfProtectionMiddleware(new SsrfValidator($opts));
        $stack      = HandlerStack::create(new MockHandler([new Response(200)]));
        $stack->push($middleware->handler());

        expect(fn () => (new Client(['handler' => $stack]))->get('http://1.2.3.4/'))
            ->toThrow(RequestException::class);
    });
});
