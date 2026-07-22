<?php

declare(strict_types=1);

/**
 * Uri::getPort() returns null both when no port is present and when the port
 * equals the scheme default, so a URL like https://host/ must still be checked
 * against port 443. Without this, a port whitelist that deliberately excludes
 * 443 would be silently bypassed by omitting the port.
 */

use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidPortException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function defaultPortDns(): FakeDnsResolver
{
    return (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
}

describe('implicit port is validated against the whitelist', function (): void {
    test('https with no explicit port is blocked when 443 is not whitelisted', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([8443]);

        expect(fn () => (new SsrfValidator($opts, defaultPortDns()))->validate('https://example.com/'))
            ->toThrow(InvalidPortException::class);
    });

    test('http with no explicit port is blocked when 80 is not whitelisted', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([8080]);

        expect(fn () => (new SsrfValidator($opts, defaultPortDns()))->validate('http://example.com/'))
            ->toThrow(InvalidPortException::class);
    });

    test('implicit and explicit default ports behave identically', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([8443]);
        $v = new SsrfValidator($opts, defaultPortDns());

        expect(fn () => $v->validate('https://example.com/'))->toThrow(InvalidPortException::class)
            ->and(fn () => $v->validate('https://example.com:443/'))->toThrow(InvalidPortException::class);
    });

    test('explicitly whitelisted non-default port still passes', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([8443])->withBlacklistIps([]);

        expect((new SsrfValidator($opts, defaultPortDns()))->isSafe('https://example.com:8443/'))->toBeTrue();
    });
});

describe('implicit port is validated against the blacklist', function (): void {
    test('http with no explicit port is blocked when 80 is blacklisted', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([])->withBlacklistPorts([80]);

        expect(fn () => (new SsrfValidator($opts, defaultPortDns()))->validate('http://example.com/'))
            ->toThrow(InvalidPortException::class);
    });

    test('https with no explicit port is blocked when 443 is blacklisted', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([])->withBlacklistPorts([443]);

        expect(fn () => (new SsrfValidator($opts, defaultPortDns()))->validate('https://example.com/'))
            ->toThrow(InvalidPortException::class);
    });
});

test('default options still allow ordinary http and https traffic', function (string $url): void {
    $opts = (new SsrfOptions)->withBlacklistIps([]);

    expect((new SsrfValidator($opts, defaultPortDns()))->isSafe($url))->toBeTrue();
})->with([
    'https implicit 443' => 'https://example.com/',
    'http implicit 80' => 'http://example.com/',
    'https explicit 443' => 'https://example.com:443/',
    'http explicit 80' => 'http://example.com:80/',
]);
