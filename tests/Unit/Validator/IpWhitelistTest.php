<?php

declare(strict_types=1);

/**
 * D2 IP Allow — IP whitelist validation.
 */

use Securized\Ssrf\Exceptions\InvalidIpException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function whitelistValidator(array $ips): SsrfValidator
{
    return new SsrfValidator(
        (new SsrfOptions())
            ->withWhitelistDomains([])
            ->withWhitelistSchemes([])
            ->withWhitelistPorts([])
            ->withBlacklistIps([])
            ->withWhitelistIps($ips)
    );
}

test('IP not in whitelist is rejected', fn () =>
    expect(fn () => whitelistValidator(['1.1.1.1/32'])->validate('http://8.8.8.8/'))
        ->toThrow(InvalidIpException::class));

test('IP matching whitelist CIDR passes', fn () =>
    expect(whitelistValidator(['1.1.1.0/24'])->isSafe('http://1.1.1.1/'))->toBeTrue());

test('IP matching whitelist exact entry passes', fn () =>
    expect(whitelistValidator(['8.8.8.8'])->isSafe('http://8.8.8.8/'))->toBeTrue());

test('empty whitelist allows any IP', fn () =>
    expect(whitelistValidator([])->isSafe('http://1.2.3.4/'))->toBeTrue());
