<?php

declare(strict_types=1);

/**
 * URL parser differential / confusion attacks.
 *
 * Tests that Guzzle's Uri parser handles edge cases safely, preventing
 * TOCTOU between validation and the actual HTTP request.
 *
 * Sources: Orange Tsai (Black Hat 2017), CVE-2026-25960 (vLLM),
 * PortSwigger URL Validation Bypass Cheat Sheet, Claroty research
 */

use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

describe('backslash confusion', function (): void {
    test('backslash before @ does not bypass host extraction', fn () =>
        // WHATWG treats \ as /, RFC3986 does not. Guzzle follows RFC3986.
        expect((new SsrfValidator(new SsrfOptions()))->isSafe('http://trusted.com\@evil.com/'))->toBeFalse());

    test('backslash in path does not affect host', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe('http://evil.com\trusted.com/'))->toBeFalse());
});

describe('null byte injection', function (): void {
    test('null byte in hostname is rejected', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe("http://evil.com%00.trusted.com/"))->toBeFalse());

    test('null byte before @ is rejected', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe("http://trusted.com%00@evil.com/"))->toBeFalse());
});

describe('encoded characters in hostname', function (): void {
    test('encoded @ (%40) in hostname', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe('http://trusted.com:80%40evil.com/'))->toBeFalse());

    test('encoded # (%23) as part of userinfo', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe('http://trusted.com%23@evil.com/'))->toBeFalse());

    test('tab in hostname', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe("http://evil.com\ttrusted.com/"))->toBeFalse());
});

describe('IPv6 zone identifiers', function (): void {
    test('zone ID %25eth0 does not bypass validation', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe('http://[fe80::1%25eth0]/'))->toBeFalse());

    test('loopback with zone ID is still blocked', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe('http://[::1%25lo]/'))->toBeFalse());
});

describe('unicode / IDN confusion', function (): void {
    test('fullwidth dot U+FF0E (127．0．0．1) is rejected', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe("http://127\u{FF0E}0\u{FF0E}0\u{FF0E}1/"))->toBeFalse());

    test('ideographic full stop U+3002 (127。0。0。1) is rejected', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe("http://127\u{3002}0\u{3002}0\u{3002}1/"))->toBeFalse());
});

describe('scheme edge cases', function (): void {
    test('data: URI is blocked by default scheme whitelist', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe('data:text/html,<h1>test</h1>'))->toBeFalse());

    test('javascript: URI is blocked', fn () =>
        expect((new SsrfValidator(new SsrfOptions()))->isSafe('javascript:alert(1)'))->toBeFalse());
});

describe('port edge cases', function (): void {
    test('explicit port 80 on http:// does not bypass port check', function (): void {
        // Guzzle returns null for default ports — port check is skipped.
        // This is safe because 80 IS the default whitelisted port.
        $v = new SsrfValidator(new SsrfOptions());
        // This should either pass or be blocked by IP — not by port
        expect($v->isSafe('http://1.1.1.1:80/'))->toBeTrue();
    });

    test('non-standard port still validated even with explicit default on different scheme', function (): void {
        // Port 443 on http:// is not the default, so Guzzle returns 443
        // and our whitelist [80, 443, 8080] should allow it
        $v = new SsrfValidator(
            (new SsrfOptions())
                ->withWhitelistDomains([])
                ->withBlacklistIps([])
                ->withWhitelistPorts([80])
        );
        // Port 8443 is not in the whitelist
        expect($v->isSafe('http://1.1.1.1:8443/'))->toBeFalse();
    });
});
