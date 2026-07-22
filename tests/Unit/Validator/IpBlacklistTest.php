<?php

declare(strict_types=1);

/**
 * D2 IP Deny / A6 Local Resource Leak / A1 Network Scan.
 *
 * Paper ref: A6 covers accessing local resources via SSRF (localhost,
 * RFC-1918, cloud metadata). D2 IP denylisting blocks these ranges.
 * All tests use IP literals to avoid DNS resolution.
 */

use Securized\Ssrf\Exceptions\InvalidIpException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function blacklistValidator(array $blacklist): SsrfValidator
{
    return new SsrfValidator(
        (new SsrfOptions())
            ->withWhitelistDomains([])
            ->withWhitelistSchemes([])
            ->withWhitelistPorts([])
            ->withBlacklistIps($blacklist)
    );
}

describe('A6 — IPv4 private/reserved ranges', function (): void {
    test('127.0.0.1 (loopback)', fn () =>
        expect(fn () => blacklistValidator(['127.0.0.0/8'])->validate('http://127.0.0.1/'))->toThrow(InvalidIpException::class));

    test('127.0.0.254 (loopback boundary)', fn () =>
        expect(fn () => blacklistValidator(['127.0.0.0/8'])->validate('http://127.0.0.254/'))->toThrow(InvalidIpException::class));

    test('10.0.0.1 (RFC-1918 class A)', fn () =>
        expect(fn () => blacklistValidator(['10.0.0.0/8'])->validate('http://10.0.0.1/'))->toThrow(InvalidIpException::class));

    test('10.255.255.255 (RFC-1918 boundary)', fn () =>
        expect(fn () => blacklistValidator(['10.0.0.0/8'])->validate('http://10.255.255.255/'))->toThrow(InvalidIpException::class));

    test('172.16.0.1 (RFC-1918 class B)', fn () =>
        expect(fn () => blacklistValidator(['172.16.0.0/12'])->validate('http://172.16.0.1/'))->toThrow(InvalidIpException::class));

    test('172.31.255.255 (/12 boundary)', fn () =>
        expect(fn () => blacklistValidator(['172.16.0.0/12'])->validate('http://172.31.255.255/'))->toThrow(InvalidIpException::class));

    test('172.32.0.0 is outside 172.16.0.0/12', fn () =>
        expect(blacklistValidator(['172.16.0.0/12'])->isSafe('http://172.32.0.0/'))->toBeTrue());

    test('192.168.0.1 (RFC-1918 class C)', fn () =>
        expect(fn () => blacklistValidator(['192.168.0.0/16'])->validate('http://192.168.0.1/'))->toThrow(InvalidIpException::class));

    test('192.168.255.255 (/16 boundary)', fn () =>
        expect(fn () => blacklistValidator(['192.168.0.0/16'])->validate('http://192.168.255.255/'))->toThrow(InvalidIpException::class));
});

describe('A6 — cloud metadata', function (): void {
    test('169.254.169.254 (AWS/GCP metadata endpoint)', fn () =>
        expect(fn () => blacklistValidator(['169.254.0.0/16'])->validate('http://169.254.169.254/'))->toThrow(InvalidIpException::class));

    test('169.254.0.1 (link-local)', fn () =>
        expect(fn () => blacklistValidator(['169.254.0.0/16'])->validate('http://169.254.0.1/'))->toThrow(InvalidIpException::class));
});

describe('A6 — other reserved ranges', function (): void {
    test('0.0.0.1 (0.0.0.0/8)', fn () =>
        expect(fn () => blacklistValidator(['0.0.0.0/8'])->validate('http://0.0.0.1/'))->toThrow(InvalidIpException::class));

    test('100.64.0.1 (shared address space RFC-6598)', fn () =>
        expect(fn () => blacklistValidator(['100.64.0.0/10'])->validate('http://100.64.0.1/'))->toThrow(InvalidIpException::class));

    test('192.0.0.1 (IETF protocol assignments)', fn () =>
        expect(fn () => blacklistValidator(['192.0.0.0/29'])->validate('http://192.0.0.1/'))->toThrow(InvalidIpException::class));

    test('192.0.2.1 (TEST-NET-1)', fn () =>
        expect(fn () => blacklistValidator(['192.0.2.0/24'])->validate('http://192.0.2.1/'))->toThrow(InvalidIpException::class));

    test('192.88.99.1 (6to4 relay)', fn () =>
        expect(fn () => blacklistValidator(['192.88.99.0/24'])->validate('http://192.88.99.1/'))->toThrow(InvalidIpException::class));

    test('198.18.0.1 (benchmarking)', fn () =>
        expect(fn () => blacklistValidator(['198.18.0.0/15'])->validate('http://198.18.0.1/'))->toThrow(InvalidIpException::class));

    test('198.51.100.1 (TEST-NET-2)', fn () =>
        expect(fn () => blacklistValidator(['198.51.100.0/24'])->validate('http://198.51.100.1/'))->toThrow(InvalidIpException::class));

    test('203.0.113.1 (TEST-NET-3)', fn () =>
        expect(fn () => blacklistValidator(['203.0.113.0/24'])->validate('http://203.0.113.1/'))->toThrow(InvalidIpException::class));

    test('224.0.0.1 (multicast)', fn () =>
        expect(fn () => blacklistValidator(['224.0.0.0/4'])->validate('http://224.0.0.1/'))->toThrow(InvalidIpException::class));

    test('240.0.0.1 (reserved)', fn () =>
        expect(fn () => blacklistValidator(['240.0.0.0/4'])->validate('http://240.0.0.1/'))->toThrow(InvalidIpException::class));
});

describe('A6 — IPv6 private ranges', function (): void {
    test('::1 (loopback)', fn () =>
        expect(fn () => blacklistValidator(['::1/128'])->validate('http://[::1]/'))->toThrow(InvalidIpException::class));

    test('fc00::1 (unique local)', fn () =>
        expect(fn () => blacklistValidator(['fc00::/7'])->validate('http://[fc00::1]/'))->toThrow(InvalidIpException::class));

    test('fd12:3456::1 (unique local fd range)', fn () =>
        expect(fn () => blacklistValidator(['fc00::/7'])->validate('http://[fd12:3456::1]/'))->toThrow(InvalidIpException::class));

    test('fe80::1 (link-local)', fn () =>
        expect(fn () => blacklistValidator(['fe80::/10'])->validate('http://[fe80::1]/'))->toThrow(InvalidIpException::class));

    test('2001:db8::1 is NOT in private blacklist', fn () =>
        expect(blacklistValidator(['fc00::/7', 'fe80::/10', '::1/128'])->isSafe('http://[2001:db8::1]/'))->toBeTrue());
});

describe('safe public IPs', function (): void {
    test('1.1.1.1 not blocked', fn () =>
        expect(blacklistValidator([])->isSafe('http://1.1.1.1/'))->toBeTrue());

    test('8.8.8.8 not blocked', fn () =>
        expect(blacklistValidator([])->isSafe('http://8.8.8.8/'))->toBeTrue());
});
