<?php

declare(strict_types=1);

/**
 * E1 — URL parser confusion / credential injection attacks.
 *
 * Paper ref: E1 covers attacks where the URL parser is confused by
 * credentials (@), query strings (?), fragments (#), or encoding to
 * extract a different host than the one actually requested.
 *
 * Case study: LibreX's home-grown get_root_domain() was bypassed by
 * appending ?example.org to evil.com:22.
 */

use Securized\Ssrf\Exceptions\InvalidDomainException;
use Securized\Ssrf\Exceptions\InvalidIpException;
use Securized\Ssrf\Exceptions\InvalidUrlException;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

describe('credential injection', function (): void {
    test('user:pass blocked by default', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions()))->validate('http://user:pass@example.com/'))
            ->toThrow(InvalidUrlException::class);
    });

    test('username-only blocked by default', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions()))->validate('http://user@example.com/'))
            ->toThrow(InvalidUrlException::class);
    });

    test('credentials allowed when sendCredentials is true', function (): void {
        $opts = (new SsrfOptions())
            ->withSendCredentials()
            ->withWhitelistDomains([])
            ->withWhitelistPorts([])
            ->withBlacklistIps(['0.0.0.0/0']);

        expect(fn () => (new SsrfValidator($opts))->validate('http://user:pass@example.com/'))
            ->toThrow(InvalidIpException::class); // passes credential check, blocked by IP
    });

    test('@ used for host confusion: http://trusted.com@evil.com/', function (): void {
        // parse_url sees trusted.com as userinfo, evil.com as host
        $opts = (new SsrfOptions())->withWhitelistDomains(['trusted\.com']);
        expect(fn () => (new SsrfValidator($opts))->validate('http://trusted.com@evil.com/'))
            ->toThrow(InvalidUrlException::class); // blocked by credential check
    });
});

describe('LibreX case study — query string injection', function (): void {
    test('evil.com:22?example.org is parsed as evil.com, not example.org', function (): void {
        $opts = (new SsrfOptions())->withWhitelistDomains(['example\.org'])->withWhitelistPorts([]);
        expect(fn () => (new SsrfValidator($opts))->validate('http://evil.com:22?example.org'))
            ->toThrow(InvalidDomainException::class);
    });
});

describe('fragment injection', function (): void {
    test('fragment does not affect host extraction', function (): void {
        $opts = (new SsrfOptions())
            ->withWhitelistDomains(['evil\.com'])
            ->withBlacklistIps(['0.0.0.0/0'])
            ->withWhitelistPorts([]);

        try {
            (new SsrfValidator($opts))->validate('http://evil.com/#trusted.com');
        } catch (InvalidDomainException) {
            $this->fail('Fragment should not affect host parsing');
        } catch (SsrfException) {
            // IP blocked — expected
        }
        expect(true)->toBeTrue();
    });
});

describe('alternative IP representations', function (): void {
    test('decimal IP 2130706433 (=127.0.0.1) is handled by URL parser', function (): void {
        // Guzzle Uri treats numeric hosts; whether this resolves to 127.0.0.1
        // depends on the HTTP client. Our validator will see it as a hostname
        // that doesn't resolve (FakeDnsResolver has no record) or as-is.
        $v = new SsrfValidator(new SsrfOptions());
        expect($v->isSafe('http://2130706433/'))->toBeFalse(); // non-resolving host
    });

    test('hex IP 0x7f000001 (=127.0.0.1) is not treated as valid IP', function (): void {
        $v = new SsrfValidator(new SsrfOptions());
        expect($v->isSafe('http://0x7f000001/'))->toBeFalse();
    });

    test('octal IP 0177.0.0.1 (=127.0.0.1) is not treated as valid IP', function (): void {
        $v = new SsrfValidator(new SsrfOptions());
        expect($v->isSafe('http://0177.0.0.1/'))->toBeFalse();
    });

    test('IPv4-mapped IPv6 ::ffff:127.0.0.1 is rejected as malformed', function (): void {
        // Guzzle Uri rejects this syntax as malformed — safe by default
        $v = new SsrfValidator(new SsrfOptions());
        expect($v->isSafe('http://[::ffff:127.0.0.1]/'))->toBeFalse();
    });
});
