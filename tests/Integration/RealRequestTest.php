<?php

declare(strict_types=1);

/**
 * Integration tests that spin up a real local HTTP server and verify
 * that SSRF protection actually blocks requests to it.
 *
 * These tests prove the validator isn't just checking strings — it
 * prevents real HTTP traffic from reaching private endpoints.
 */

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Http\Middleware\SsrfProtectionMiddleware;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

const SERVER_HOST = '127.0.0.1';
const SERVER_PORT = 18923;
const SERVER_URL = 'http://'.SERVER_HOST.':'.SERVER_PORT;

beforeAll(function (): void {
    $serverScript = __DIR__.'/server.php';
    $cmd = sprintf(
        'php -S %s:%d %s > /dev/null 2>&1 & echo $!',
        SERVER_HOST, SERVER_PORT, escapeshellarg($serverScript)
    );
    $pid = (int) trim(shell_exec($cmd));
    expect($pid)->toBeGreaterThan(0);

    // Store PID for cleanup
    $GLOBALS['__test_server_pid'] = $pid;

    // Wait for server to be ready
    $ready = false;
    for ($i = 0; $i < 50; $i++) {
        $sock = @fsockopen(SERVER_HOST, SERVER_PORT, $errno, $errstr, 0.1);
        if ($sock) {
            fclose($sock);
            $ready = true;
            break;
        }
        usleep(100_000); // 100ms
    }
    expect($ready)->toBeTrue('Server did not start in time');
});

afterAll(function (): void {
    $pid = $GLOBALS['__test_server_pid'] ?? null;
    if ($pid) {
        posix_kill($pid, SIGTERM);
    }
});

function unprotectedClient(): Client
{
    return new Client(['timeout' => 5]);
}

function protectedClient(?SsrfOptions $opts = null): Client
{
    $stack = HandlerStack::create();
    $stack->push(SsrfProtectionMiddleware::make($opts));

    return new Client(['handler' => $stack, 'timeout' => 5]);
}

test('sanity: unprotected client reaches local server', function (): void {
    $response = unprotectedClient()->get(SERVER_URL.'/ping');
    $body = json_decode($response->getBody()->getContents(), true);

    expect($response->getStatusCode())->toBe(200);
    expect($body['reached'])->toBeTrue();
    expect($body['uri'])->toBe('/ping');
});

describe('protected client blocks loopback', function (): void {
    test('127.0.0.1 is blocked', function (): void {
        expect(fn () => protectedClient()->get(SERVER_URL.'/'))
            ->toThrow(RequestException::class);
    });

    test('127.0.0.1 with explicit port is blocked', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([80, 443, SERVER_PORT]);
        expect(fn () => protectedClient($opts)->get(SERVER_URL.'/'))
            ->toThrow(RequestException::class);
    });
});

describe('shorthand IP bypasses are blocked', function (): void {
    test('127.1 resolves to 127.0.0.1 and is blocked', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([80, 443, SERVER_PORT]);
        expect(fn () => protectedClient($opts)->get('http://127.1:'.SERVER_PORT.'/'))
            ->toThrow(RequestException::class);
    });

    test('127.0.1 resolves to 127.0.0.1 and is blocked', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([80, 443, SERVER_PORT]);
        expect(fn () => protectedClient($opts)->get('http://127.0.1:'.SERVER_PORT.'/'))
            ->toThrow(RequestException::class);
    });

    test('0 resolves to 0.0.0.0 and is blocked', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([80, 443, SERVER_PORT]);
        expect(fn () => protectedClient($opts)->get('http://0:'.SERVER_PORT.'/'))
            ->toThrow(RequestException::class);
    });
});

describe('DNS pinning with real request', function (): void {
    test('pinned request replaces host but preserves Host header', function (): void {
        // Use the IP directly with pin_dns — should work and reach server
        $opts = (new SsrfOptions)
            ->withPinDns()
            ->withBlacklistIps([])    // allow loopback for this test
            ->withWhitelistPorts([80, 443, SERVER_PORT])
            ->withWhitelistDomains([]);

        $client = protectedClient($opts);
        $response = $client->get(SERVER_URL.'/pinned');
        $body = json_decode($response->getBody()->getContents(), true);

        expect($response->getStatusCode())->toBe(200);
        expect($body['reached'])->toBeTrue();
        expect($body['uri'])->toBe('/pinned');
    });

    test('a pinned hostname connects to the validated IP and keeps its Host header', function (): void {
        // "pinned.invalid" cannot resolve through real DNS, so reaching the
        // server proves curl used the CURLOPT_RESOLVE entry for the connection.
        $opts = (new SsrfOptions)
            ->withPinDns()
            ->withBlacklistIps([])
            ->withWhitelistPorts([SERVER_PORT]);
        $dns = (new FakeDnsResolver)->addRecord('pinned.invalid', SERVER_HOST);

        $stack = HandlerStack::create();
        $stack->push((new SsrfProtectionMiddleware(new SsrfValidator($opts, $dns)))->handler());
        $client = new Client(['handler' => $stack, 'timeout' => 5]);

        $response = $client->get('http://pinned.invalid:'.SERVER_PORT.'/pinned');
        $body = json_decode($response->getBody()->getContents(), true);

        expect($body['reached'])->toBeTrue()
            ->and($body['host'])->toBe('pinned.invalid:'.SERVER_PORT);
    });
});

describe('scheme blocking prevents real connections', function (): void {
    test('file:// is blocked before any connection attempt', function (): void {
        expect(fn () => protectedClient()->get('file:///etc/passwd'))
            ->toThrow(RequestException::class);
    });

    test('gopher:// is blocked before any connection attempt', function (): void {
        expect(fn () => protectedClient()->get('gopher://'.SERVER_HOST.':'.SERVER_PORT.'/'))
            ->toThrow(RequestException::class);
    });
});

describe('port blocking prevents real connections', function (): void {
    test('non-whitelisted port is blocked even when server is listening', function (): void {
        // Default whitelist is [80, 443, 8080] — our server port is not in it
        expect(fn () => protectedClient()->get(SERVER_URL.'/'))
            ->toThrow(RequestException::class);
    });

    test('whitelisted port allows connection (when IP is also allowed)', function (): void {
        $opts = (new SsrfOptions)
            ->withWhitelistPorts([80, 443, SERVER_PORT])
            ->withBlacklistIps([])    // allow loopback for this test
            ->withWhitelistDomains([]);

        $response = protectedClient($opts)->get(SERVER_URL.'/allowed');
        $body = json_decode($response->getBody()->getContents(), true);

        expect($body['reached'])->toBeTrue();
    });
});
