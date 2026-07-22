<?php

declare(strict_types=1);

use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidDomainException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function patternDns(): FakeDnsResolver
{
    return (new FakeDnsResolver)
        ->addRecord('evil.com', '93.184.216.34')
        ->addRecord('api.example.com', '93.184.216.34')
        ->addRecord('apixexample.com', '93.184.216.34')
        ->addRecord('deep.api.example.com', '93.184.216.34')
        ->addRecord('example.com', '93.184.216.34');
}

function patternOpts(): SsrfOptions
{
    return (new SsrfOptions)->withBlacklistIps([]);
}

describe('dots are literal, not regex wildcards', function (): void {
    test('a dot in a whitelist pattern does not match an arbitrary character', function (): void {
        $opts = patternOpts()->withWhitelistDomains(['api.example.com']);

        expect((new SsrfValidator($opts, patternDns()))->isSafe('http://apixexample.com/'))->toBeFalse();
    });

    test('the intended host still matches its own pattern', function (): void {
        $opts = patternOpts()->withWhitelistDomains(['api.example.com']);

        expect((new SsrfValidator($opts, patternDns()))->isSafe('http://api.example.com/'))->toBeTrue();
    });

    test('a dot in a blacklist pattern does not over-match', function (): void {
        $opts = patternOpts()->withBlacklistDomains(['api.example.com']);

        expect((new SsrfValidator($opts, patternDns()))->isSafe('http://apixexample.com/'))->toBeTrue();
    });
});

describe('* acts as a wildcard', function (): void {
    test('*.example.com matches a subdomain', function (): void {
        $opts = patternOpts()->withBlacklistDomains(['*.example.com']);

        expect(fn () => (new SsrfValidator($opts, patternDns()))->validate('http://api.example.com/'))
            ->toThrow(InvalidDomainException::class);
    });

    test('*.example.com matches a nested subdomain', function (): void {
        $opts = patternOpts()->withBlacklistDomains(['*.example.com']);

        expect(fn () => (new SsrfValidator($opts, patternDns()))->validate('http://deep.api.example.com/'))
            ->toThrow(InvalidDomainException::class);
    });

    test('*.example.com does not match the bare apex domain', function (): void {
        $opts = patternOpts()->withBlacklistDomains(['*.example.com']);

        expect((new SsrfValidator($opts, patternDns()))->isSafe('http://example.com/'))->toBeTrue();
    });

    test('*.example.com does not match an unrelated host', function (): void {
        $opts = patternOpts()->withBlacklistDomains(['*.example.com']);

        expect((new SsrfValidator($opts, patternDns()))->isSafe('http://evil.com/'))->toBeTrue();
    });

    test('a whitelist wildcard admits matching subdomains only', function (): void {
        $opts = patternOpts()->withWhitelistDomains(['*.example.com']);
        $v = new SsrfValidator($opts, patternDns());

        expect($v->isSafe('http://api.example.com/'))->toBeTrue()
            ->and($v->isSafe('http://evil.com/'))->toBeFalse();
    });
});

describe('regex metacharacters are treated literally', function (): void {
    test('a regex-style pattern does not match the host it would have as a regex', function (): void {
        $opts = patternOpts()->withBlacklistDomains(['(.*)\.example\.com']);

        expect((new SsrfValidator($opts, patternDns()))->isSafe('http://api.example.com/'))->toBeTrue();
    });

    test('an unbalanced bracket is just a literal, never an error', function (): void {
        $opts = patternOpts()->withBlacklistDomains(['*invalid[']);

        expect((new SsrfValidator($opts, patternDns()))->isSafe('http://evil.com/'))->toBeTrue();
    });
});

describe('matching is case-insensitive', function (): void {
    test('an uppercase pattern matches a lowercase host', function (): void {
        $opts = patternOpts()->withBlacklistDomains(['API.EXAMPLE.COM']);

        expect(fn () => (new SsrfValidator($opts, patternDns()))->validate('http://api.example.com/'))
            ->toThrow(InvalidDomainException::class);
    });

    test('an uppercase host matches a lowercase pattern', function (): void {
        $opts = patternOpts()->withBlacklistDomains(['api.example.com']);

        expect(fn () => (new SsrfValidator($opts, patternDns()))->validate('http://API.EXAMPLE.COM/'))
            ->toThrow(InvalidDomainException::class);
    });
});
