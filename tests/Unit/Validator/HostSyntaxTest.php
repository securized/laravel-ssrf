<?php

declare(strict_types=1);

use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidIpException;
use Securized\Ssrf\Exceptions\InvalidUrlException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

describe('hosts curl would read as a different name', function (): void {
    test('are rejected even when DNS answers for the literal name', function (string $host): void {
        $dns = (new FakeDnsResolver)->addRecord($host, '93.184.216.34');

        expect(fn () => (new SsrfValidator(new SsrfOptions, $dns))->validate("http://{$host}/"))
            ->toThrow(InvalidUrlException::class);
    })->with([
        'percent-encoded letter' => ['%61.attacker.test'],
        'percent-encoded dot' => ['a%2eattacker.test'],
        'percent-encoded loopback' => ['%6cocalhost'],
        'leading hyphen' => ['-attacker.test'],
        'leading dot' => ['.attacker.test'],
        'plus sign' => ['+attacker.test'],
        'comma' => ['a,b.test'],
        'asterisk' => ['*.attacker.test'],
    ]);

    test('a bracketed host that is not IPv6 is rejected', function (): void {
        expect((new SsrfValidator(new SsrfOptions, new FakeDnsResolver))->isSafe('http://[fe80::1%25eth0]/'))->toBeFalse();
    });
});

describe('hosts the syntax check must leave alone', function (): void {
    test('ordinary names still resolve', function (string $host): void {
        $dns = (new FakeDnsResolver)->addRecord($host, '93.184.216.34');

        expect((new SsrfValidator(new SsrfOptions, $dns))->validate("http://{$host}/")['host'])->toBe($host);
    })->with([
        'plain' => ['example.com'],
        'hyphenated' => ['my-app.example.com'],
        'underscore label' => ['_dmarc.example.com'],
        'punycode' => ['xn--bcher-kva.example'],
        'unicode' => ['bücher.example'],
        'trailing dot' => ['example.com.'],
    ]);
});

describe('IP whitelist without pinning', function (): void {
    test('a host is rejected unless every resolved address is whitelisted', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('mixed.example', '8.8.8.8', '93.184.216.34');
        $options = (new SsrfOptions)->withWhitelistIps(['93.184.216.34']);

        expect(fn () => (new SsrfValidator($options, $dns))->validate('https://mixed.example/'))
            ->toThrow(InvalidIpException::class);
    });

    test('a host whose addresses are all whitelisted passes', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('ok.example', '93.184.216.34', '93.184.216.35');
        $options = (new SsrfOptions)->withWhitelistIps(['93.184.216.0/24']);

        expect((new SsrfValidator($options, $dns))->validate('https://ok.example/')['ips'])
            ->toBe(['93.184.216.34', '93.184.216.35']);
    });

    test('with pinning the request is limited to the whitelisted addresses instead', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('mixed.example', '8.8.8.8', '93.184.216.34');
        $options = (new SsrfOptions)->withWhitelistIps(['93.184.216.34'])->withPinDns();

        expect((new SsrfValidator($options, $dns))->validate('https://mixed.example/')['ips'])->toBe(['93.184.216.34']);
    });
});
