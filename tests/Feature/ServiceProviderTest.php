<?php

declare(strict_types=1);

use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\Facades\Ssrf;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;
use Securized\Ssrf\Tests\TestCase;

uses(TestCase::class);

describe('Service provider bindings', function (): void {
    test('SsrfOptions is bound in container', function (): void {
        expect(app(SsrfOptions::class))->toBeInstanceOf(SsrfOptions::class);
    });

    test('SsrfValidator is bound in container', function (): void {
        expect(app(SsrfValidator::class))->toBeInstanceOf(SsrfValidator::class);
    });

    test('each resolution returns a fresh instance', function (): void {
        $a = app(SsrfOptions::class);
        $b = app(SsrfOptions::class);
        expect($a)->not->toBe($b);
    });

    test('SsrfOptions is built from config on each resolution', function (): void {
        config()->set('ssrf.whitelist.schemes', ['https']);
        $opts = app(SsrfOptions::class);
        expect($opts->whitelistSchemes)->toBe(['https']);
    });
});

describe('Ssrf facade', function (): void {
    test('facade resolves to SsrfValidator', function (): void {
        expect(Ssrf::getFacadeRoot())->toBeInstanceOf(SsrfValidator::class);
    });

    test('isSafe() returns false for localhost', function (): void {
        expect(Ssrf::isSafe('http://127.0.0.1/'))->toBeFalse();
    });

    test('isSafe() returns false for file:// scheme', function (): void {
        expect(Ssrf::isSafe('file:///etc/passwd'))->toBeFalse();
    });

    test('isSafe() returns false for empty string', function (): void {
        expect(Ssrf::isSafe(''))->toBeFalse();
    });

    test('safeUrl() throws SsrfException for localhost', function (): void {
        expect(fn () => Ssrf::safeUrl('http://127.0.0.1/'))->toThrow(SsrfException::class);
    });

    test('safeUrl() throws SsrfException for file:// scheme', function (): void {
        expect(fn () => Ssrf::safeUrl('file:///etc/passwd'))->toThrow(SsrfException::class);
    });

    test('validate() throws SsrfException for gopher:// scheme', function (): void {
        expect(fn () => Ssrf::validate('gopher://internal:70/1'))->toThrow(SsrfException::class);
    });

    test('validate() returns result array for a public IP with no restrictions', function (): void {
        $opts = (new SsrfOptions)
            ->withWhitelistDomains([])
            ->withWhitelistSchemes([])
            ->withWhitelistPorts([])
            ->withBlacklistIps([]);

        $result = (new SsrfValidator($opts))->validate('http://1.1.1.1/');
        expect($result)->toHaveKeys(['url', 'host', 'ips']);
        expect($result['host'])->toBe('1.1.1.1');
    });
});
