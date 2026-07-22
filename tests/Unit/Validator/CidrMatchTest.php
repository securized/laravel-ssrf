<?php

declare(strict_types=1);

/**
 * cidrMatch() — all branches of IPv4/IPv6 CIDR matching.
 */

use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function cidrValidator(array $blacklist): SsrfValidator
{
    return new SsrfValidator(
        (new SsrfOptions())
            ->withWhitelistDomains([])
            ->withWhitelistSchemes([])
            ->withWhitelistPorts([])
            ->withBlacklistIps($blacklist)
    );
}

describe('IPv4 CIDR', function (): void {
    test('exact match without slash', function (): void {
        $v = cidrValidator(['1.2.3.4']);
        expect($v->isSafe('http://1.2.3.4/'))->toBeFalse();
        expect($v->isSafe('http://1.2.3.5/'))->toBeTrue();
    });

    test('/0 matches all addresses', function (): void {
        $v = cidrValidator(['0.0.0.0/0']);
        expect($v->isSafe('http://1.2.3.4/'))->toBeFalse();
        expect($v->isSafe('http://255.255.255.255/'))->toBeFalse();
    });

    test('/32 matches single host', function (): void {
        $v = cidrValidator(['1.2.3.4/32']);
        expect($v->isSafe('http://1.2.3.4/'))->toBeFalse();
        expect($v->isSafe('http://1.2.3.5/'))->toBeTrue();
    });

    test('invalid subnet does not crash', function (): void {
        expect(cidrValidator(['not.an.ip/8'])->isSafe('http://10.0.0.1/'))->toBeTrue();
    });
});

describe('IPv6 CIDR', function (): void {
    test('exact match without slash', function (): void {
        $v = cidrValidator(['::1']);
        expect($v->isSafe('http://[::1]/'))->toBeFalse();
        expect($v->isSafe('http://[::2]/'))->toBeTrue();
    });

    test('/128 matches single host', function (): void {
        $v = cidrValidator(['::1/128']);
        expect($v->isSafe('http://[::1]/'))->toBeFalse();
        expect($v->isSafe('http://[::2]/'))->toBeTrue();
    });

    test('fe80::/10 covers fe80:: to febf::', function (): void {
        $v = cidrValidator(['fe80::/10']);
        expect($v->isSafe('http://[fe80::1]/'))->toBeFalse();
        expect($v->isSafe('http://[fec0::1]/'))->toBeTrue();
    });

    test('invalid IPv6 subnet does not crash', function (): void {
        expect(cidrValidator(['not::valid::ipv6/64'])->isSafe('http://[::1]/'))->toBeTrue();
    });
});

describe('cross-family CIDR', function (): void {
    test('IPv6 CIDR does not match IPv4', fn () =>
        expect(cidrValidator(['::1/128'])->isSafe('http://1.2.3.4/'))->toBeTrue());

    test('IPv4 CIDR does not match IPv6', fn () =>
        expect(cidrValidator(['127.0.0.0/8'])->isSafe('http://[::1]/'))->toBeTrue());
});
