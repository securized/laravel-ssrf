<?php

declare(strict_types=1);

/**
 * D1 Domain — domain allow/deny validation.
 */

use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidDomainException;
use Securized\Ssrf\Exceptions\InvalidIpException;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

test('domain not in whitelist is rejected', function (): void {
    $opts = (new SsrfOptions)->withWhitelistDomains(['trusted\.com']);
    expect(fn () => (new SsrfValidator($opts))->validate('http://evil.com/'))
        ->toThrow(InvalidDomainException::class);
});

test('domain matching whitelist regex passes', function (): void {
    $opts = (new SsrfOptions)
        ->withWhitelistDomains(['(.*)\.example\.com'])
        ->withBlacklistIps(['0.0.0.0/0'])
        ->withWhitelistPorts([]);
    $dns = (new FakeDnsResolver)->addRecord('api.example.com', '93.184.216.34');
    // Passes domain check, blocked by IP
    expect(fn () => (new SsrfValidator($opts, $dns))->validate('http://api.example.com/'))
        ->toThrow(InvalidIpException::class);
});

test('domain in blacklist is rejected', function (): void {
    $opts = (new SsrfOptions)->withWhitelistDomains([])->withBlacklistDomains(['evil\.com']);
    expect(fn () => (new SsrfValidator($opts))->validate('http://evil.com/'))
        ->toThrow(InvalidDomainException::class);
});

test('blacklist wins when domain matches both lists', function (): void {
    $opts = (new SsrfOptions)->withWhitelistDomains(['evil\.com'])->withBlacklistDomains(['evil\.com']);
    expect(fn () => (new SsrfValidator($opts))->validate('http://evil.com/'))
        ->toThrow(InvalidDomainException::class);
});

test('domain matching is case-insensitive', function (): void {
    $opts = (new SsrfOptions)->withWhitelistDomains([])->withBlacklistDomains(['evil\.com']);
    expect(fn () => (new SsrfValidator($opts))->validate('http://EVIL.COM/'))
        ->toThrow(InvalidDomainException::class);
});

test('non-resolving hostname throws InvalidDomainException', function (): void {
    $opts = (new SsrfOptions)->withWhitelistDomains([]);
    expect(fn () => (new SsrfValidator($opts))->validate('http://this-host-xyzzy123.invalid/'))
        ->toThrow(InvalidDomainException::class);
});

test('empty whitelist allows any domain', function (): void {
    $opts = (new SsrfOptions)->withWhitelistDomains([])->withBlacklistIps(['0.0.0.0/0']);
    try {
        (new SsrfValidator($opts))->validate('http://example.com/');
    } catch (InvalidDomainException) {
        $this->fail('Empty whitelist should allow any domain');
    } catch (SsrfException) {
    }
    expect(true)->toBeTrue();
});
