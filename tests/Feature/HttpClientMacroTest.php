<?php

declare(strict_types=1);

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\Tests\TestCase;

uses(TestCase::class);

// ---------------------------------------------------------------------------
// Http::ssrf() macro — registered by service provider
// ---------------------------------------------------------------------------

describe('Http::ssrf() macro', function (): void {
    test('macro is registered', function (): void {
        expect(Http::hasMacro('ssrf'))->toBeTrue();
    });

    test('withSsrfProtection macro is registered', function (): void {
        expect(Http::hasMacro('withSsrfProtection'))->toBeTrue();
    });

    test('ssrf() blocks request to localhost', function (): void {
        Http::fake(); // prevent real network calls
        expect(fn () => Http::ssrf()->get('http://127.0.0.1/'))->toThrow(ConnectionException::class);
    });

    test('ssrf() blocks file:// scheme (A4 bridging)', function (): void {
        Http::fake();
        expect(fn () => Http::ssrf()->get('file:///etc/passwd'))->toThrow(ConnectionException::class);
    });

    test('ssrf() blocks gopher:// scheme (A4 bridging → RCE)', function (): void {
        Http::fake();
        expect(fn () => Http::ssrf()->get('gopher://internal:70/1'))->toThrow(ConnectionException::class);
    });

    test('ssrf() blocks RFC-1918 range 10.x.x.x (A6 local resource leak)', function (): void {
        Http::fake();
        expect(fn () => Http::ssrf()->get('http://10.0.0.1/'))->toThrow(ConnectionException::class);
    });

    test('ssrf() blocks 169.254.169.254 (cloud metadata – A6)', function (): void {
        Http::fake();
        expect(fn () => Http::ssrf()->get('http://169.254.169.254/latest/meta-data/'))->toThrow(ConnectionException::class);
    });

    test('ssrf() blocks 192.168.x.x (RFC-1918)', function (): void {
        Http::fake();
        expect(fn () => Http::ssrf()->get('http://192.168.1.100/'))->toThrow(ConnectionException::class);
    });

    test('ssrf() allows a faked safe URL (literal public IP)', function (): void {
        // Use a literal IP to avoid DNS resolution in tests; 1.1.1.1 is public (Cloudflare DNS)
        // and not in any blacklisted range.
        Http::fake(['https://1.1.1.1/*' => Http::response('ok', 200)]);
        $opts     = (new SsrfOptions())->withWhitelistPorts([80, 443]);
        $response = Http::ssrf($opts)->get('https://1.1.1.1/');
        expect($response->status())->toBe(200);
    });

    test('withSsrfProtection() is identical to ssrf()', function (): void {
        Http::fake();
        expect(fn () => Http::withSsrfProtection()->get('http://127.0.0.1/'))->toThrow(ConnectionException::class);
    });

    test('ssrf() chains with other PendingRequest methods', function (): void {
        Http::fake(['https://1.1.1.1/*' => Http::response(['data' => 1], 200)]);
        $opts     = (new SsrfOptions())->withWhitelistPorts([80, 443]);
        $response = Http::ssrf($opts)
            ->withHeaders(['Accept' => 'application/json'])
            ->timeout(5)
            ->get('https://1.1.1.1/');
        expect($response->json('data'))->toBe(1);
    });
});

// ---------------------------------------------------------------------------
// Per-request options override
// ---------------------------------------------------------------------------

describe('Http::ssrf() with options override', function (): void {
    test('HTTPS-only override blocks HTTP', function (): void {
        Http::fake();
        $opts = (new SsrfOptions())
            ->withWhitelistSchemes(['https'])
            ->withWhitelistDomains([])
            ->withBlacklistIps(['0.0.0.0/0']);

        expect(fn () => Http::ssrf($opts)->get('http://example.com/'))->toThrow(ConnectionException::class);
    });

    test('null options use default config', function (): void {
        Http::fake();
        expect(fn () => Http::ssrf(null)->get('http://127.0.0.1/'))->toThrow(ConnectionException::class);
    });
});

// ---------------------------------------------------------------------------
// auto_protect — global middleware
// ---------------------------------------------------------------------------

describe('auto_protect config', function (): void {
    test('auto_protect=false does not apply global middleware (Http::get still works for faked safe URLs)', function (): void {
        config()->set('ssrf.auto_protect', false);
        Http::fake(['https://example.com/*' => Http::response('ok', 200)]);
        // Without auto_protect, Http::get should work normally (no SSRF middleware globally)
        $response = Http::get('https://example.com/');
        expect($response->status())->toBe(200);
    });

    test('auto_protect=true blocks localhost even without ssrf() macro', function (): void {
        // Rebuild the service provider with auto_protect enabled
        config()->set('ssrf.auto_protect', true);
        Http::fake();

        // Boot the macro registration fresh
        $provider = new \Securized\Ssrf\SsrfServiceProvider(app());
        $provider->packageBooted();

        expect(fn () => Http::get('http://127.0.0.1/'))->toThrow(ConnectionException::class);
    });
});
