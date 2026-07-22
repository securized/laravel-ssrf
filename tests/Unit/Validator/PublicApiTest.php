<?php

declare(strict_types=1);

use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function permissiveOpts(): SsrfOptions
{
    return (new SsrfOptions)
        ->withWhitelistDomains([])
        ->withWhitelistSchemes(['http', 'https'])
        ->withWhitelistPorts([])
        ->withBlacklistIps([])
        ->withWhitelistIps(['1.2.3.4']);
}

describe('isSafe()', function (): void {
    test('returns false for blocked URL', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('http://127.0.0.1/'))->toBeFalse());

    test('returns false for file:// scheme', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe('file:///etc/passwd'))->toBeFalse());

    test('returns false for empty URL', fn () => expect((new SsrfValidator(new SsrfOptions))->isSafe(''))->toBeFalse());

    test('returns true for safe URL', fn () => expect((new SsrfValidator(permissiveOpts()))->isSafe('http://1.2.3.4/'))->toBeTrue());
});

describe('safeUrl()', function (): void {
    test('returns validated URL', fn () => expect((new SsrfValidator(permissiveOpts()))->safeUrl('http://1.2.3.4/path'))->toBe('http://1.2.3.4/path'));

    test('throws on blocked URL', fn () => expect(fn () => (new SsrfValidator(new SsrfOptions))->safeUrl('http://127.0.0.1/'))->toThrow(SsrfException::class));
});

describe('validate() return structure', function (): void {
    test('returns url, host, ips keys', function (): void {
        $result = (new SsrfValidator(permissiveOpts()))->validate('http://1.2.3.4/');
        expect($result)->toHaveKeys(['url', 'host', 'ips']);
        expect($result['host'])->toBe('1.2.3.4');
        expect($result['ips'])->toContain('1.2.3.4');
    });
});

describe('URL reconstruction', function (): void {
    test('path preserved', fn () => expect((new SsrfValidator(permissiveOpts()))->validate('http://1.2.3.4/some/path')['url'])->toBe('http://1.2.3.4/some/path'));

    test('query string preserved', fn () => expect((new SsrfValidator(permissiveOpts()))->validate('http://1.2.3.4/path?foo=bar&baz=qux')['url'])->toBe('http://1.2.3.4/path?foo=bar&baz=qux'));

    test('fragment preserved', fn () => expect((new SsrfValidator(permissiveOpts()))->validate('http://1.2.3.4/path#section')['url'])->toBe('http://1.2.3.4/path#section'));

    test('port preserved', fn () => expect((new SsrfValidator(permissiveOpts()->withWhitelistPorts([8080])))->validate('http://1.2.3.4:8080/')['url'])->toBe('http://1.2.3.4:8080/'));

    test('credentials preserved when allowed', fn () => expect((new SsrfValidator(permissiveOpts()->withSendCredentials()))->validate('http://user:secret@1.2.3.4/')['url'])->toBe('http://user:secret@1.2.3.4/'));
});
