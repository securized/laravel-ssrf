<?php

declare(strict_types=1);

/**
 * Port validation limits which ports an SSRF can reach, blocking use of the
 * request as a port scanner against internal services.
 */

use Securized\Ssrf\Exceptions\InvalidPortException;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

describe('dangerous ports blocked', function (): void {
    test('SSH port 22 blocked', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions))->validate('http://example.com:22/'))
            ->toThrow(InvalidPortException::class);
    });

    test('Redis port 6379 blocked', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions))->validate('http://example.com:6379/'))
            ->toThrow(InvalidPortException::class);
    });

    test('MySQL port 3306 blocked', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions))->validate('http://example.com:3306/'))
            ->toThrow(InvalidPortException::class);
    });
});

describe('port whitelist and blacklist', function (): void {
    $blockAllIps = fn () => (new SsrfOptions)->withBlacklistIps(['0.0.0.0/0'])->withWhitelistDomains([]);

    test('port 80 allowed by default', function () use ($blockAllIps): void {
        try {
            (new SsrfValidator($blockAllIps()))->validate('http://example.com:80/');
        } catch (InvalidPortException) {
            $this->fail('Port 80 should be allowed');
        } catch (SsrfException) {
        }
        expect(true)->toBeTrue();
    });

    test('port 443 allowed by default', function () use ($blockAllIps): void {
        try {
            (new SsrfValidator($blockAllIps()))->validate('https://example.com:443/');
        } catch (InvalidPortException) {
            $this->fail('Port 443 should be allowed');
        } catch (SsrfException) {
        }
        expect(true)->toBeTrue();
    });

    test('port 8080 allowed by default', function () use ($blockAllIps): void {
        try {
            (new SsrfValidator($blockAllIps()))->validate('http://example.com:8080/');
        } catch (InvalidPortException) {
            $this->fail('Port 8080 should be allowed');
        } catch (SsrfException) {
        }
        expect(true)->toBeTrue();
    });

    test('empty whitelist allows any port', function () use ($blockAllIps): void {
        $opts = $blockAllIps()->withWhitelistPorts([]);
        try {
            (new SsrfValidator($opts))->validate('http://example.com:22/');
        } catch (InvalidPortException) {
            $this->fail('Empty whitelist should allow any port');
        } catch (SsrfException) {
        }
        expect(true)->toBeTrue();
    });

    test('blacklist blocks even when whitelist is empty', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([])->withBlacklistPorts([22])->withWhitelistDomains([]);
        expect(fn () => (new SsrfValidator($opts))->validate('http://example.com:22/'))
            ->toThrow(InvalidPortException::class);
    });

    test('blacklist wins over whitelist', function (): void {
        $opts = (new SsrfOptions)->withWhitelistPorts([80, 443, 22])->withBlacklistPorts([22]);
        expect(fn () => (new SsrfValidator($opts))->validate('http://example.com:22/'))
            ->toThrow(InvalidPortException::class);
    });

    test('no port in URL skips port validation', function () use ($blockAllIps): void {
        try {
            (new SsrfValidator($blockAllIps()))->validate('http://example.com/');
        } catch (InvalidPortException) {
            $this->fail('No port should skip validation');
        } catch (SsrfException) {
        }
        expect(true)->toBeTrue();
    });
});
