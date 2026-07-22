<?php

declare(strict_types=1);

/**
 * D1 – URL Validation: basic URL parsing and structure checks.
 */

use Securized\Ssrf\Exceptions\InvalidSchemeException;
use Securized\Ssrf\Exceptions\InvalidUrlException;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

test('empty string throws InvalidUrlException', function (): void {
    expect(fn () => (new SsrfValidator(new SsrfOptions()))->validate(''))
        ->toThrow(InvalidUrlException::class);
});

test('whitespace-only string throws InvalidUrlException', function (): void {
    expect(fn () => (new SsrfValidator(new SsrfOptions()))->validate('   '))
        ->toThrow(InvalidUrlException::class);
});

test('relative path without host throws InvalidUrlException', function (): void {
    expect(fn () => (new SsrfValidator(new SsrfOptions()))->validate('/etc/passwd'))
        ->toThrow(InvalidUrlException::class);
});

test('URL without scheme defaults to http', function (): void {
    $v = new SsrfValidator((new SsrfOptions())->withWhitelistSchemes(['https']));
    expect(fn () => $v->validate('//example.com/'))->toThrow(InvalidSchemeException::class);
});

test('scheme-less URL with http whitelisted passes scheme check', function (): void {
    $opts = (new SsrfOptions())
        ->withWhitelistSchemes(['http'])
        ->withWhitelistDomains([])
        ->withWhitelistPorts([])
        ->withBlacklistIps(['0.0.0.0/0']);

    try {
        (new SsrfValidator($opts))->validate('//example.com/');
    } catch (InvalidSchemeException) {
        $this->fail('scheme-less URL should default to http');
    } catch (SsrfException) {
        // IP blocked — expected
    }
    expect(true)->toBeTrue();
});
