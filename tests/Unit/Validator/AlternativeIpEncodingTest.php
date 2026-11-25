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

use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidIpException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

describe('decimal/hex/octal IPv4 representations', function (): void {

    test('decimal 2130706433 (= 127.0.0.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://2130706433/'))->toBeFalse());

    test('hex 0x7f000001 (= 127.0.0.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://0x7f000001/'))->toBeFalse());

    test('octal 0177.0.0.1 (= 127.0.0.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://0177.0.0.1/'))->toBeFalse());

    test('shorthand 127.1 (= 127.0.0.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://127.1/'))->toBeFalse());

    test('shorthand 127.0.1 (= 127.0.0.1) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://127.0.1/'))->toBeFalse());

    test('leading zeros 127.000.000.001 is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://127.000.000.001/'))->toBeFalse());

    test('http://0/ (= 0.0.0.0) is blocked', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://0/'))->toBeFalse());
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

describe('other IPv6 forms that carry an IPv4 address', function (): void {
    test('is blocked', function (string $ip): void {
        expect((new SsrfValidator(new SsrfOptions))->isSafe("http://[{$ip}]/"))->toBeFalse();
    })->with([
        'NAT64 metadata' => ['64:ff9b::a9fe:a9fe'],
        'NAT64 loopback' => ['64:ff9b::7f00:1'],
        'NAT64 private' => ['64:ff9b::c0a8:101'],
        'local-use NAT64 metadata' => ['64:ff9b:1::a9fe:a9fe'],
        'IPv4-compatible loopback' => ['::7f00:1'],
        'IPv4-compatible metadata' => ['::a9fe:a9fe'],
        'Teredo' => ['2001:0:4136:e378:8000:63bf:3fff:fdd2'],
    ]);

    test('a NAT64 address for a public IPv4 host is allowed, as DNS64 networks resolve every IPv4-only host this way', function (): void {
        expect((new SsrfValidator(new SsrfOptions))->validate('http://[64:ff9b::5db8:d822]/')['ips'])->toBe(['64:ff9b::5db8:d822']);
    });

    test('a NAT64 address is checked against a custom IPv4 blacklist entry', function (): void {
        $options = (new SsrfOptions)->withBlacklistIps(['93.184.216.0/24']);

        expect((new SsrfValidator($options))->isSafe('http://[64:ff9b::5db8:d822]/'))->toBeFalse();
    });

    test('a hostname resolving to a NAT64 form of an internal address is blocked', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('rebind.test', '64:ff9b::a9fe:a9fe');

        expect((new SsrfValidator(new SsrfOptions, $dns))->isSafe('http://rebind.test/'))->toBeFalse();
    });
});

describe('embedded IPv4 addresses are checked wherever they are carried', function (): void {
    $configPublishedBefore = fn (): SsrfOptions => (new SsrfOptions)->withBlacklistIps(array_values(array_diff(
        (new SsrfOptions)->blacklistIps,
        ['::/96', '::ffff:0:0/96', '::ffff:0:0:0/96', '64:ff9b:1::/48', '2001::/32', '2002::/16'],
    )));

    test('an internal target is blocked by the IPv4 lists alone', function (string $ip) use ($configPublishedBefore): void {
        expect((new SsrfValidator($configPublishedBefore()))->isSafe("http://[{$ip}]/"))->toBeFalse();
    })->with([
        'IPv4-compatible' => ['::a9fe:a9fe'],
        'IPv4-mapped' => ['::ffff:a9fe:a9fe'],
        'IPv4-translated' => ['::ffff:0:a9fe:a9fe'],
        'NAT64' => ['64:ff9b::a9fe:a9fe'],
        '6to4' => ['2002:a9fe:a9fe::1'],
        'Teredo server' => ['2001:0:a9fe:a9fe::1'],
        'Teredo client, inverted' => ['2001:0:5db8:d822::5601:5601'],
        'ISATAP, private' => ['2a00:1450::5efe:a9fe:a9fe'],
        'ISATAP, global bit' => ['2a00:1450::200:5efe:7f00:1'],
    ]);

    test('IPv4-translated addresses are blacklisted by default', function (): void {
        expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[::ffff:0:5db8:d822]/'))->toBeFalse();
    });

    test('an ISATAP address carrying a public IPv4 address is left alone', function (): void {
        expect((new SsrfValidator(new SsrfOptions))->isSafe('http://[2a00:1450::200:5efe:5db8:d822]/'))->toBeTrue();
    });

    test('a network-specific NAT64 prefix is unwrapped once configured', function (string $prefix, string $internal, string $public): void {
        $validator = new SsrfValidator((new SsrfOptions)->withNat64Prefixes(['64:ff9b::/96', $prefix]));

        expect((new SsrfValidator(new SsrfOptions))->isSafe("http://[{$internal}]/"))->toBeTrue()
            ->and($validator->isSafe("http://[{$internal}]/"))->toBeFalse()
            ->and($validator->isSafe("http://[{$public}]/"))->toBeTrue();
    })->with([
        '/96' => ['2a00:1450:64::/96', '2a00:1450:64::a9fe:a9fe', '2a00:1450:64::5db8:d822'],
        '/64' => ['2a00:1450:64:1::/64', '2a00:1450:64:1:a9:fea9:fe00:0', '2a00:1450:64:1:5d:b8d8:2200:0'],
        '/48' => ['2a00:1450:64::/48', '2a00:1450:64:a9fe:a9:fe00::', '2a00:1450:64:5db8:d8:2200::'],
        '/32' => ['2a00:1450::/32', '2a00:1450:a9fe:a9fe::', '2a00:1450:5db8:d822::'],
    ]);

    test('unwrapping follows the worked examples in RFC 6052 section 2.4', function (string $prefix, string $address): void {
        $options = (new SsrfOptions)->withBlacklistIps(['192.0.2.33'])->withNat64Prefixes([$prefix]);

        expect(fn () => (new SsrfValidator($options))->validate("http://[{$address}]/"))
            ->toThrow(InvalidIpException::class, '(carrying 192.0.2.33)');
    })->with([
        ['2001:db8::/32', '2001:db8:c000:221::'],
        ['2001:db8:100::/40', '2001:db8:1c0:2:21::'],
        ['2001:db8:122::/48', '2001:db8:122:c000:2:2100::'],
        ['2001:db8:122:300::/56', '2001:db8:122:3c0:0:221::'],
        ['2001:db8:122:344::/64', '2001:db8:122:344:c0:2:2100::'],
        ['2001:db8:122:344::/96', '2001:db8:122:344::192.0.2.33'],
    ]);

    test('the message names the address that was resolved and the one it carries', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions))->validate('http://[64:ff9b::a9fe:a9fe]/'))
            ->toThrow(InvalidIpException::class, 'resolves to "64:ff9b::a9fe:a9fe" (carrying 169.254.169.254) which matches blacklisted range "169.254.0.0/16"');
    });
});
