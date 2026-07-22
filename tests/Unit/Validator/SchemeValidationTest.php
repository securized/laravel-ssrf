<?php

declare(strict_types=1);

/**
 * D1 Scheme / A4 Bridging Attack — scheme allow/deny validation.
 *
 * Paper ref: A4 covers gopher, ftp, file, dict protocols that enable
 * protocol bridging → RCE. D1 scheme validation is the primary defense.
 */

use Securized\Ssrf\Exceptions\InvalidSchemeException;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

describe('A4 — blocked schemes', function (): void {
    test('file:// blocked (local file access)', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions))->validate('file:///etc/passwd'))
            ->toThrow(InvalidSchemeException::class);
    });

    test('gopher:// blocked (protocol bridging → RCE)', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions))->validate('gopher://example.com:70/1'))
            ->toThrow(InvalidSchemeException::class);
    });

    test('ftp:// blocked', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions))->validate('ftp://example.com/file.txt'))
            ->toThrow(InvalidSchemeException::class);
    });

    test('dict:// blocked', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions))->validate('dict://example.com:2628/'))
            ->toThrow(InvalidSchemeException::class);
    });

    test('ldap:// blocked', function (): void {
        expect(fn () => (new SsrfValidator(new SsrfOptions))->validate('ldap://example.com/'))
            ->toThrow(InvalidSchemeException::class);
    });
});

describe('D1 — scheme whitelist/blacklist', function (): void {
    test('http allowed by default', function (): void {
        $v = new SsrfValidator((new SsrfOptions)->withBlacklistIps(['0.0.0.0/0'])->withWhitelistDomains([]));
        try {
            $v->validate('http://example.com/');
        } catch (InvalidSchemeException) {
            $this->fail('http should be allowed');
        } catch (SsrfException) {
        }
        expect(true)->toBeTrue();
    });

    test('https allowed by default', function (): void {
        $v = new SsrfValidator((new SsrfOptions)->withBlacklistIps(['0.0.0.0/0'])->withWhitelistDomains([]));
        try {
            $v->validate('https://example.com/');
        } catch (InvalidSchemeException) {
            $this->fail('https should be allowed');
        } catch (SsrfException) {
        }
        expect(true)->toBeTrue();
    });

    test('scheme is normalised to lowercase', function (): void {
        $v = new SsrfValidator((new SsrfOptions)->withBlacklistIps(['0.0.0.0/0'])->withWhitelistDomains([])->withWhitelistSchemes(['http']));
        try {
            $v->validate('HTTP://example.com/');
        } catch (InvalidSchemeException) {
            $this->fail('HTTP should normalise to http');
        } catch (SsrfException) {
        }
        expect(true)->toBeTrue();
    });

    test('empty whitelist allows any scheme', function (): void {
        $v = new SsrfValidator((new SsrfOptions)->withWhitelistSchemes([])->withBlacklistIps(['0.0.0.0/0'])->withWhitelistDomains([]));
        try {
            $v->validate('gopher://example.com/');
        } catch (InvalidSchemeException) {
            $this->fail('empty whitelist should allow any scheme');
        } catch (SsrfException) {
        }
        expect(true)->toBeTrue();
    });

    test('blacklist blocks even when whitelist is empty', function (): void {
        $opts = (new SsrfOptions)->withWhitelistSchemes([])->withBlacklistSchemes(['gopher'])->withWhitelistDomains([]);
        expect(fn () => (new SsrfValidator($opts))->validate('gopher://example.com/'))
            ->toThrow(InvalidSchemeException::class);
    });

    test('scheme not in non-empty whitelist is rejected', function (): void {
        expect(fn () => (new SsrfValidator((new SsrfOptions)->withWhitelistSchemes(['https'])))->validate('http://example.com/'))
            ->toThrow(InvalidSchemeException::class);
    });
});
