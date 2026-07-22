<?php

declare(strict_types=1);

/**
 * DNS rebinding: a hostname resolves to a safe IP during validation and to a
 * private IP for the actual request. Pinning resolves once and substitutes the
 * validated IP, closing that window.
 */

use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function pinningOpts(bool $pin = true): SsrfOptions
{
    return (new SsrfOptions)
        ->withWhitelistDomains([])
        ->withWhitelistSchemes(['http', 'https'])
        ->withWhitelistPorts([])
        ->withBlacklistIps([])
        ->withPinDns($pin);
}

test('pin_dns replaces host with resolved IP in URL', function (): void {
    $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
    $v = new SsrfValidator(pinningOpts(), $dns);
    $result = $v->validate('http://example.com/path');

    expect($result['url'])->toContain('93.184.216.34');
    expect($result['host'])->toBe('example.com');
    expect($result['ips'])->toBe(['93.184.216.34']);
});

test('pin_dns preserves original host in host key', function (): void {
    $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
    $result = (new SsrfValidator(pinningOpts(), $dns))->validate('http://example.com/');

    expect($result['host'])->toBe('example.com');
});

test('without pin_dns URL host is unchanged', function (): void {
    $dns = (new FakeDnsResolver)->addRecord('example.com', '93.184.216.34');
    $result = (new SsrfValidator(pinningOpts(false), $dns))->validate('http://example.com/path?q=1#frag');

    expect($result['url'])->toBe('http://example.com/path?q=1#frag');
});

test('pin_dns with IP literal is a no-op', function (): void {
    $v = new SsrfValidator(pinningOpts());
    $result = $v->validate('http://1.2.3.4/');

    expect($result['url'])->toBe('http://1.2.3.4/');
});

test('rebinding is defeated: the first resolve is pinned for the request', function (): void {
    $dns = (new FakeDnsResolver)->addRecord('rebind.attacker.com', '93.184.216.34');
    $v = new SsrfValidator(pinningOpts(), $dns);

    $result = $v->validate('http://rebind.attacker.com/');
    // The URL now points to the safe IP, not the hostname that could rebind
    expect($result['url'])->toContain('93.184.216.34');
    expect($result['url'])->not->toContain('rebind.attacker.com');
});
