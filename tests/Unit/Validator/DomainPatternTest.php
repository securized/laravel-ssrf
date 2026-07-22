<?php

declare(strict_types=1);

/**
 * D1 Domain — domain pattern handling.
 *
 * Domain lists are regular expressions. A malformed pattern is a configuration
 * error, and must fail closed: preg_match() returns false on a bad pattern, and
 * treating that as "no match" would let a typo'd blacklist entry silently allow
 * every host through.
 */

use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidDomainException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function patternDns(): FakeDnsResolver
{
    return (new FakeDnsResolver())->addRecord('evil.com', '93.184.216.34');
}

describe('malformed domain patterns fail closed', function (): void {
    test('invalid blacklist pattern throws instead of allowing the host', function (): void {
        $opts = (new SsrfOptions())
            ->withBlacklistIps([])
            ->withBlacklistDomains(['*invalid[']);

        expect(fn () => (new SsrfValidator($opts, patternDns()))->validate('http://evil.com/'))
            ->toThrow(InvalidDomainException::class);
    });

    test('invalid whitelist pattern throws instead of allowing the host', function (): void {
        $opts = (new SsrfOptions())
            ->withBlacklistIps([])
            ->withWhitelistDomains(['*invalid[']);

        expect(fn () => (new SsrfValidator($opts, patternDns()))->validate('http://evil.com/'))
            ->toThrow(InvalidDomainException::class);
    });

    test('isSafe() reports false for a malformed pattern rather than true', function (): void {
        $opts = (new SsrfOptions())
            ->withBlacklistIps([])
            ->withBlacklistDomains(['(unclosed']);

        expect((new SsrfValidator($opts, patternDns()))->isSafe('http://evil.com/'))->toBeFalse();
    });

    test('the exception names the offending pattern', function (): void {
        $opts = (new SsrfOptions())
            ->withBlacklistIps([])
            ->withBlacklistDomains(['*invalid[']);

        expect(fn () => (new SsrfValidator($opts, patternDns()))->validate('http://evil.com/'))
            ->toThrow(InvalidDomainException::class, '*invalid[');
    });

    test('the exception explains why the pattern is invalid', function (): void {
        $opts = (new SsrfOptions())
            ->withBlacklistIps([])
            ->withBlacklistDomains(['(unclosed']);

        expect(fn () => (new SsrfValidator($opts, patternDns()))->validate('http://evil.com/'))
            ->toThrow(InvalidDomainException::class, 'missing closing parenthesis');
    });
});

describe('valid domain patterns still work', function (): void {
    test('a well-formed blacklist pattern blocks a matching host', function (): void {
        $opts = (new SsrfOptions())
            ->withBlacklistIps([])
            ->withBlacklistDomains(['(.*)\.internal\.test']);
        $dns = (new FakeDnsResolver())->addRecord('api.internal.test', '93.184.216.34');

        expect(fn () => (new SsrfValidator($opts, $dns))->validate('http://api.internal.test/'))
            ->toThrow(InvalidDomainException::class);
    });

    test('a well-formed blacklist pattern allows a non-matching host', function (): void {
        $opts = (new SsrfOptions())
            ->withBlacklistIps([])
            ->withBlacklistDomains(['(.*)\.internal\.test']);

        expect((new SsrfValidator($opts, patternDns()))->isSafe('http://evil.com/'))->toBeTrue();
    });
});
