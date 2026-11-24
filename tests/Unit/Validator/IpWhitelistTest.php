<?php

declare(strict_types=1);

use Securized\Ssrf\Dns\FakeDnsResolver;
use Securized\Ssrf\Exceptions\InvalidIpException;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

function whitelistValidator(array $ips): SsrfValidator
{
    return new SsrfValidator(
        (new SsrfOptions)
            ->withWhitelistDomains([])
            ->withWhitelistSchemes([])
            ->withWhitelistPorts([])
            ->withBlacklistIps([])
            ->withWhitelistIps($ips)
    );
}

test('IP not in whitelist is rejected', fn () => expect(fn () => whitelistValidator(['1.1.1.1/32'])->validate('http://8.8.8.8/'))
    ->toThrow(InvalidIpException::class));

test('IP matching whitelist CIDR passes', fn () => expect(whitelistValidator(['1.1.1.0/24'])->isSafe('http://1.1.1.1/'))->toBeTrue());

test('IP matching whitelist exact entry passes', fn () => expect(whitelistValidator(['8.8.8.8'])->isSafe('http://8.8.8.8/'))->toBeTrue());

test('empty whitelist allows any IP', fn () => expect(whitelistValidator([])->isSafe('http://1.2.3.4/'))->toBeTrue());

describe('IP whitelist without pinning', function (): void {
    test('a host is rejected unless every resolved address is whitelisted', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('mixed.example', '8.8.8.8', '93.184.216.34');
        $options = (new SsrfOptions)->withWhitelistIps(['93.184.216.34']);

        expect(fn () => (new SsrfValidator($options, $dns))->validate('https://mixed.example/'))
            ->toThrow(InvalidIpException::class);
    });

    test('a host whose addresses are all whitelisted passes', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('ok.example', '93.184.216.34', '93.184.216.35');
        $options = (new SsrfOptions)->withWhitelistIps(['93.184.216.0/24']);

        expect((new SsrfValidator($options, $dns))->validate('https://ok.example/')['ips'])
            ->toBe(['93.184.216.34', '93.184.216.35']);
    });

    test('a caller that pins is limited to the whitelisted addresses instead', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('mixed.example', '8.8.8.8', '93.184.216.34');
        $validator = new SsrfValidator((new SsrfOptions)->withWhitelistIps(['93.184.216.34'])->withPinDns(), $dns);

        expect($validator->validate('https://mixed.example/', pinned: true)['ips'])->toBe(['93.184.216.34'])
            ->and($validator->safeUrl('https://mixed.example/'))->toBe('https://93.184.216.34/');
    });

    test('pin_dns alone does not relax the rule for callers that pin nothing', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('mixed.example', '8.8.8.8', '93.184.216.34');
        $validator = new SsrfValidator((new SsrfOptions)->withWhitelistIps(['93.184.216.34'])->withPinDns(), $dns);

        expect($validator->isSafe('https://mixed.example/'))->toBeFalse()
            ->and(fn () => $validator->validate('https://mixed.example/'))->toThrow(InvalidIpException::class);
    });
});

describe('IP whitelist behind NAT64', function (): void {
    test('a NAT64 address is whitelisted by the IPv4 address it forwards to', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('ok.example', '64:ff9b::5db8:d822');
        $options = (new SsrfOptions)->withWhitelistIps(['93.184.216.0/24']);

        expect((new SsrfValidator($options, $dns))->validate('https://ok.example/')['ips'])->toBe(['64:ff9b::5db8:d822']);
    });

    test('a NAT64 address forwarding elsewhere is still rejected', function (): void {
        $dns = (new FakeDnsResolver)->addRecord('other.example', '64:ff9b::808:808');
        $options = (new SsrfOptions)->withWhitelistIps(['93.184.216.0/24']);

        expect((new SsrfValidator($options, $dns))->isSafe('https://other.example/'))->toBeFalse();
    });
});
