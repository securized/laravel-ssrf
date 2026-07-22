<?php

declare(strict_types=1);

/**
 * Alternative IP encoding bypass attempts.
 *
 * Attackers encode private IPs in decimal, hex, octal, or IPv6 mapped
 * formats to bypass naive string-based blacklists. Our validator uses
 * Guzzle Uri + filter_var + CIDR matching, so these should all fail safely.
 *
 * Sources: PayloadsAllTheThings, HackTricks URL Format Bypass
 */

use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

describe('decimal/hex/octal IPv4 representations', function (): void {
    // These bypass filter_var(FILTER_VALIDATE_IP) but gethostbyname/curl
    // resolves them to real IPs. The gethostbyname fallback in NativeDnsResolver
    // catches them so the IP blacklist can reject the resolved address.

    test('decimal 2130706433 (= 127.0.0.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://2130706433/'))->toBeFalse());

    test('hex 0x7f000001 (= 127.0.0.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://0x7f000001/'))->toBeFalse());

    test('octal 0177.0.0.1 (= 127.0.0.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://0177.0.0.1/'))->toBeFalse());

    test('shorthand 127.1 (= 127.0.0.1) is blocked via gethostbyname fallback', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://127.1/'))->toBeFalse());

    test('shorthand 127.0.1 (= 127.0.0.1) is blocked via gethostbyname fallback', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://127.0.1/'))->toBeFalse());

    test('leading zeros 127.000.000.001 is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://127.000.000.001/'))->toBeFalse());

    test('http://0/ (= 0.0.0.0) is blocked via gethostbyname fallback', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://0/'))->toBeFalse());
});

describe('IPv4-mapped IPv6 addresses', function (): void {
    test('::ffff:127.0.0.1 is rejected (malformed for Guzzle)', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[::ffff:127.0.0.1]/'))->toBeFalse());

    test('::ffff:7f00:1 (hex form of 127.0.0.1) is blocked by ::ffff:0:0/96', function (): void {
        // This is valid IPv6 — if Guzzle accepts it, our blacklist ::ffff:0:0/96 should catch it
        expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[::ffff:7f00:1]/'))->toBeFalse();
    });

    test('::ffff:a9fe:a9fe (= 169.254.169.254 metadata) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[::ffff:a9fe:a9fe]/'))->toBeFalse());

    test('::ffff:c0a8:101 (= 192.168.1.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[::ffff:c0a8:101]/'))->toBeFalse());
});

describe('6to4 addresses (2002::/16)', function (): void {
    test('2002:7f00:1::1 (encodes 127.0.0.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[2002:7f00:1::1]/'))->toBeFalse());

    test('2002:a9fe:a9fe::1 (encodes 169.254.169.254) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[2002:a9fe:a9fe::1]/'))->toBeFalse());

    test('2002:c0a8:101::1 (encodes 192.168.1.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[2002:c0a8:101::1]/'))->toBeFalse());
});

describe('expanded IPv6 forms', function (): void {
    test('[0000::1] (expanded loopback) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[0000::1]/'))->toBeFalse());

    test('[0:0:0:0:0:0:0:1] (fully expanded loopback) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[0:0:0:0:0:0:0:1]/'))->toBeFalse());

    test('[::] (unspecified address) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[::]/'))->toBeFalse());

    test('[0:0:0:0:0:0:0:0] (expanded unspecified) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[0:0:0:0:0:0:0:0]/'))->toBeFalse());
});

describe('new IPv6 blacklist ranges', function (): void {
    test('ff02::1 (IPv6 multicast) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[ff02::1]/'))->toBeFalse());

    test('2001:db8::1 (documentation range) is blocked by default', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[2001:db8::1]/'))->toBeFalse());

    test('100::1 (discard prefix RFC 6666) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[100::1]/'))->toBeFalse());

    test('fd00:ec2::254 (AWS IPv6 metadata) is blocked by fc00::/7', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[fd00:ec2::254]/'))->toBeFalse());
});
