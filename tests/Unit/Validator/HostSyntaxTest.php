<?php

declare(strict_types=1);

use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidDomainException;
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

    test('a bracketed host that is not IPv6 is rejected', function (string $url): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');

        expect(fn () => (new SsrfValidator((new SsrfOptions)->withBlacklistIps([]), $dns))->validate($url))
            ->toThrow(InvalidUrlException::class);
    })->with(['http://[fe80::1%25eth0]/', 'http://[example.com]/', 'http://[127.0.0.1]/']);
});

describe('hosts are validated under the name curl looks up', function (): void {
    test('ordinary names are unchanged', function (string $host): void {
        $dns = (new FakeDnsResolver)->addRecord($host, '93.184.216.34');

        expect((new SsrfValidator(new SsrfOptions, $dns))->validate("http://{$host}/")['host'])->toBe($host);
    })->with([
        'plain' => ['example.com'],
        'hyphenated' => ['my-app.example.com'],
        'underscore label' => ['_dmarc.example.com'],
        'punycode' => ['xn--bcher-kva.example'],
    ]);

    test('IDN and trailing-dot forms resolve as the plain ASCII name', function (string $host, string $lookedUp): void {
        $dns = (new FakeDnsResolver)->addRecord($lookedUp, '93.184.216.34');

        expect((new SsrfValidator(new SsrfOptions, $dns))->validate("http://{$host}/")['host'])->toBe($lookedUp);
    })->with([
        'unicode' => ['bücher.example', 'xn--bcher-kva.example'],
        'full-width letter' => ["\u{FF45}xample.com", 'example.com'],
        'trailing dot' => ['example.com.', 'example.com'],
    ])->skip(! function_exists('idn_to_ascii'), 'ext-intl is not installed');

    test('a blacklisted domain cannot be reached under another spelling', function (string $host): void {
        $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
        $validator = new SsrfValidator((new SsrfOptions)->withBlacklistDomains(['example.com']), $dns);

        expect(fn () => $validator->validate("http://{$host}/"))->toThrow(InvalidDomainException::class);
    })->with(['example.com', 'example.com.', "\u{FF45}xample.com", 'EXAMPLE.com'])
        ->skip(! function_exists('idn_to_ascii'), 'ext-intl is not installed');

    test('full-width digits are read as the IP they map to', function (): void {
        expect((new SsrfValidator(new SsrfOptions, new FakeDnsResolver))->isSafe("http://127\u{FF0E}0\u{FF0E}0\u{FF0E}1/"))->toBeFalse();
    });
});
