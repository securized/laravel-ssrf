<?php

declare(strict_types=1);

/**
 * Numeric hosts that are not dotted-decimal IPv4.
 *
 * curl reads 0177.0.0.1, 0x7f000001, 2130706433 and 127.1 as 127.0.0.1, but
 * PHP, libc and curl disagree on the edge cases from one build to the next
 * (trailing dots, leading zeros, hex in gethostbyname). Asking DNS about them
 * is worse: a resolver that answers with a public IP gets the URL approved
 * while curl connects to loopback. They must be rejected before any lookup.
 */

use Securized\Ssrf\Dns\DnsResolver;
use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidUrlException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

/** A resolver that answers every name with a public IP and records what it was asked. */
function answeringResolver(array &$asked): DnsResolver
{
    return new class($asked) implements DnsResolver
    {
        public function __construct(private array &$asked) {}

        public function resolve(string $host): array
        {
            $this->asked[] = $host;

            return ['93.184.216.34'];
        }
    };
}

describe('non-canonical numeric hosts', function (): void {
    test('are rejected without a DNS lookup, even if DNS would answer', function (string $host): void {
        $asked = [];
        $validator = new SsrfValidator(new SsrfOptions, answeringResolver($asked));

        expect(fn () => $validator->validate("http://{$host}/"))->toThrow(InvalidUrlException::class)
            ->and($asked)->toBe([]);
    })->with([
        'octal' => ['0177.0.0.1'],
        'octal, padded' => ['00000177.0.0.1'],
        'hex integer' => ['0x7f000001'],
        'hex, uppercase' => ['0X7F000001'],
        'hex shorthand' => ['0x7f.1'],
        'mixed octal and hex' => ['0177.0.0.0x1'],
        'decimal integer' => ['2130706433'],
        'two parts' => ['127.1'],
        'three parts' => ['127.0.1'],
        'zero' => ['0'],
        'leading zeros' => ['127.000.000.001'],
        'invalid octal digit' => ['09.0.0.1'],
        'trailing dot' => ['127.0.0.1.'],
        'octal with trailing dot' => ['0177.0.0.1.'],
        'octet out of range' => ['127.0.0.256'],
        'five parts' => ['1.2.3.4.5'],
        'overflowing integer' => ['0x100000000'],
        'metadata as integer' => ['2852039166'],
        'name with a numeric last label' => ['example.123'],
        'name with a hex last label' => ['example.0x7f'],
    ]);

    test('are rejected with the default resolver too', function (string $host): void {
        expect((new SsrfValidator(new SsrfOptions))->isSafe("http://{$host}/"))->toBeFalse();
    })->with(['0177.0.0.1', '0x7f000001', '2130706433', '127.1']);
});

describe('hosts the rule must leave alone', function (): void {
    test('a dotted-decimal IPv4 address is still validated as an IP', function (): void {
        $asked = [];
        $validator = new SsrfValidator(new SsrfOptions, answeringResolver($asked));

        expect($validator->validate('http://93.184.216.34/')['ips'])->toBe(['93.184.216.34'])
            ->and($validator->isSafe('http://127.0.0.1/'))->toBeFalse()
            ->and($asked)->toBe([]);
    });

    test('hostnames containing digits are still resolved', function (string $host): void {
        $dns = (new FakeDnsResolver)->addRecord($host, '93.184.216.34');

        expect((new SsrfValidator(new SsrfOptions, $dns))->validate("http://{$host}/")['host'])->toBe($host);
    })->with([
        'digits in a label' => ['example1.com'],
        'numeric first label' => ['123.example.com'],
        'ip-shaped prefix' => ['127.0.0.1.example.com'],
        'hex-looking first label' => ['0x7f.example.com'],
        'trailing dot on a name' => ['example.com.'],
        'punycode tld' => ['example.xn--p1ai'],
    ]);

    test('IPv6 literals are not treated as numeric IPv4', function (): void {
        $validator = new SsrfValidator((new SsrfOptions)->withBlacklistIps([]), new FakeDnsResolver);

        expect($validator->validate('http://[2606:4700::1111]/')['ips'])->toBe(['2606:4700::1111'])
            ->and((new SsrfValidator(new SsrfOptions, new FakeDnsResolver))->isSafe('http://[::1]/'))->toBeFalse();
    });
});
