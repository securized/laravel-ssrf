<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Validator;
use Securized\Ssrf\Rules\SsrfSafeUrl;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\Tests\TestCase;

uses(TestCase::class);

function permissiveOptions(): SsrfOptions
{
    return (new SsrfOptions())
        ->withWhitelistDomains([])
        ->withWhitelistSchemes([])
        ->withWhitelistPorts([])
        ->withBlacklistIps([]);
}

// ---------------------------------------------------------------------------
// Non-string values
// ---------------------------------------------------------------------------

describe('SsrfSafeUrl — non-string values', function (): void {
    test('integer value fails with type message', function (): void {
        $rule   = new SsrfSafeUrl(permissiveOptions());
        $result = Validator::make(['url' => 12345], ['url' => [$rule]]);
        expect($result->fails())->toBeTrue();
        expect($result->errors()->first('url'))->toBe('The url must be a string URL.');
    });

    test('null value fails with type message', function (): void {
        $rule   = new SsrfSafeUrl(permissiveOptions());
        $result = Validator::make(['url' => null], ['url' => [$rule]]);
        expect($result->fails())->toBeTrue();
        expect($result->errors()->first('url'))->toBe('The url must be a string URL.');
    });

    test('array value fails with type message', function (): void {
        $rule   = new SsrfSafeUrl(permissiveOptions());
        $result = Validator::make(['url' => ['http://example.com']], ['url' => [$rule]]);
        expect($result->fails())->toBeTrue();
        expect($result->errors()->first('url'))->toBe('The url must be a string URL.');
    });
});

// ---------------------------------------------------------------------------
// Blocked URLs
// ---------------------------------------------------------------------------

describe('SsrfSafeUrl — blocked URLs', function (): void {
    test('localhost blocked and returns safe message (no IP disclosed)', function (): void {
        $rule   = new SsrfSafeUrl();
        $result = Validator::make(['url' => 'http://127.0.0.1/admin'], ['url' => [$rule]]);
        expect($result->fails())->toBeTrue();
        expect($result->errors()->first('url'))->toBe('The url contains a URL that is not permitted.');
        expect($result->errors()->first('url'))->not->toContain('127.0.0.1');
    });

    test('blocked scheme fails validation', function (): void {
        $result = Validator::make(['url' => 'file:///etc/passwd'], ['url' => [new SsrfSafeUrl()]]);
        expect($result->fails())->toBeTrue();
    });

    test('gopher scheme fails validation (A4 bridging attack)', function (): void {
        $result = Validator::make(['url' => 'gopher://internal.host:70/1'], ['url' => [new SsrfSafeUrl()]]);
        expect($result->fails())->toBeTrue();
    });

    test('cloud metadata endpoint 169.254.169.254 fails validation (A6)', function (): void {
        $result = Validator::make(['url' => 'http://169.254.169.254/'], ['url' => [new SsrfSafeUrl()]]);
        expect($result->fails())->toBeTrue();
    });

    test('empty string fails validation when required', function (): void {
        $result = Validator::make(['url' => ''], ['url' => ['required', new SsrfSafeUrl()]]);
        expect($result->fails())->toBeTrue();
    });

    test('non-resolving hostname fails validation', function (): void {
        $result = Validator::make(
            ['url' => 'http://this-host-definitely-does-not-exist-xyzzy.invalid/'],
            ['url' => [new SsrfSafeUrl()]]
        );
        expect($result->fails())->toBeTrue();
    });
});

// ---------------------------------------------------------------------------
// Passing URLs
// ---------------------------------------------------------------------------

describe('SsrfSafeUrl — passing URLs', function (): void {
    test('public IP with no restrictions passes', function (): void {
        $result = Validator::make(['url' => 'http://1.1.1.1/'], ['url' => [new SsrfSafeUrl(permissiveOptions())]]);
        expect($result->passes())->toBeTrue();
    });
});

// ---------------------------------------------------------------------------
// Custom options
// ---------------------------------------------------------------------------

describe('SsrfSafeUrl — custom options', function (): void {
    test('HTTPS-only rule blocks HTTP', function (): void {
        $opts   = (new SsrfOptions())->withWhitelistSchemes(['https'])->withWhitelistDomains([]);
        $result = Validator::make(['url' => 'http://example.com/'], ['url' => [new SsrfSafeUrl($opts)]]);
        expect($result->fails())->toBeTrue();
    });

    test('attribute name is interpolated in type error message', function (): void {
        $result = Validator::make(['webhook_url' => 99], ['webhook_url' => [new SsrfSafeUrl(permissiveOptions())]]);
        expect($result->errors()->first('webhook_url'))->toBe('The webhook url must be a string URL.');
    });

    test('attribute name is interpolated in SSRF error message', function (): void {
        $result = Validator::make(['webhook_url' => 'http://127.0.0.1/'], ['webhook_url' => [new SsrfSafeUrl()]]);
        expect($result->errors()->first('webhook_url'))->toBe('The webhook url contains a URL that is not permitted.');
    });
});

// ---------------------------------------------------------------------------
// Container resolution
// ---------------------------------------------------------------------------

describe('SsrfSafeUrl — container resolution', function (): void {
    test('rule resolves SsrfValidator from container when no options given', function (): void {
        $result = Validator::make(['url' => 'http://127.0.0.1/'], ['url' => [new SsrfSafeUrl()]]);
        expect($result->fails())->toBeTrue();
    });

    test('file:// blocked by default scheme whitelist', function (): void {
        $result = Validator::make(['url' => 'file:///etc/passwd'], ['url' => [new SsrfSafeUrl()]]);
        expect($result->fails())->toBeTrue();
    });
});
