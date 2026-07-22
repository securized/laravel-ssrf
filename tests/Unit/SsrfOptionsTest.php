<?php

declare(strict_types=1);

use Securized\Ssrf\SsrfOptions;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

describe('SsrfOptions defaults', function (): void {
    test('sendCredentials defaults to false', function (): void {
        expect((new SsrfOptions)->sendCredentials)->toBeFalse();
    });

    test('pinDns defaults to false', function (): void {
        expect((new SsrfOptions)->pinDns)->toBeFalse();
    });

    test('whitelist ports default to 80, 443, 8080', function (): void {
        expect((new SsrfOptions)->whitelistPorts)->toBe([80, 443, 8080]);
    });

    test('whitelist schemes default to http and https', function (): void {
        expect((new SsrfOptions)->whitelistSchemes)->toBe(['http', 'https']);
    });

    test('whitelist IPs default to empty', function (): void {
        expect((new SsrfOptions)->whitelistIps)->toBe([]);
    });

    test('whitelist domains default to empty', function (): void {
        expect((new SsrfOptions)->whitelistDomains)->toBe([]);
    });

    test('blacklist ports default to empty', function (): void {
        expect((new SsrfOptions)->blacklistPorts)->toBe([]);
    });

    test('blacklist schemes default to empty', function (): void {
        expect((new SsrfOptions)->blacklistSchemes)->toBe([]);
    });

    test('blacklist domains default to empty', function (): void {
        expect((new SsrfOptions)->blacklistDomains)->toBe([]);
    });

    test('default blacklist IPs contain all RFC-1918 and special ranges', function (): void {
        $ips = (new SsrfOptions)->blacklistIps;
        // IPv4
        expect($ips)->toContain('127.0.0.0/8');
        expect($ips)->toContain('10.0.0.0/8');
        expect($ips)->toContain('172.16.0.0/12');
        expect($ips)->toContain('192.168.0.0/16');
        expect($ips)->toContain('169.254.0.0/16');
        // IPv6
        expect($ips)->toContain('::/128');
        expect($ips)->toContain('::1/128');
        expect($ips)->toContain('::ffff:0:0/96');
        expect($ips)->toContain('2002::/16');
        expect($ips)->toContain('fc00::/7');
        expect($ips)->toContain('fe80::/10');
        expect($ips)->toContain('ff00::/8');
    });
});

// ---------------------------------------------------------------------------
// fromConfig()
// ---------------------------------------------------------------------------

describe('SsrfOptions::fromConfig()', function (): void {
    test('builds from a complete config array', function (): void {
        $opts = SsrfOptions::fromConfig([
            'send_credentials' => true,
            'pin_dns' => true,
            'whitelist' => [
                'ips' => ['1.2.3.4'],
                'ports' => [443],
                'domains' => ['example.com'],
                'schemes' => ['https'],
            ],
            'blacklist' => [
                'ips' => ['10.0.0.0/8'],
                'ports' => [22],
                'domains' => ['evil.com'],
                'schemes' => ['gopher'],
            ],
        ]);

        expect($opts->sendCredentials)->toBeTrue();
        expect($opts->pinDns)->toBeTrue();
        expect($opts->whitelistIps)->toBe(['1.2.3.4']);
        expect($opts->whitelistPorts)->toBe([443]);
        expect($opts->whitelistDomains)->toBe(['example.com']);
        expect($opts->whitelistSchemes)->toBe(['https']);
        expect($opts->blacklistIps)->toBe(['10.0.0.0/8']);
        expect($opts->blacklistPorts)->toBe([22]);
        expect($opts->blacklistDomains)->toBe(['evil.com']);
        expect($opts->blacklistSchemes)->toBe(['gopher']);
    });

    test('missing keys fall back to defaults', function (): void {
        $opts = SsrfOptions::fromConfig([]);
        expect($opts->sendCredentials)->toBeFalse();
        expect($opts->pinDns)->toBeFalse();
        expect($opts->whitelistPorts)->toBe([80, 443, 8080]);
        expect($opts->whitelistSchemes)->toBe(['http', 'https']);
        expect($opts->blacklistIps)->toContain('127.0.0.0/8');
    });

    test('port values are cast to int', function (): void {
        $opts = SsrfOptions::fromConfig([
            'whitelist' => ['ports' => ['80', '443']],
            'blacklist' => ['ports' => ['22']],
        ]);
        expect($opts->whitelistPorts)->toBe([80, 443]);
        expect($opts->blacklistPorts)->toBe([22]);
    });

    test('IP values are cast to string', function (): void {
        $opts = SsrfOptions::fromConfig([
            'whitelist' => ['ips' => [123]],
            'blacklist' => ['ips' => []],
        ]);
        expect($opts->whitelistIps)->toBe(['123']);
    });
});

// ---------------------------------------------------------------------------
// Wither methods — immutability
// ---------------------------------------------------------------------------

describe('wither methods are immutable', function (): void {
    test('withPinDns returns new instance with pin_dns=true', function (): void {
        $a = new SsrfOptions;
        $b = $a->withPinDns();
        expect($a->pinDns)->toBeFalse();
        expect($b->pinDns)->toBeTrue();
        expect($a)->not->toBe($b);
    });

    test('withPinDns(false) turns pin_dns off', function (): void {
        $a = (new SsrfOptions)->withPinDns();
        $b = $a->withPinDns(false);
        expect($b->pinDns)->toBeFalse();
    });

    test('withSendCredentials returns new instance with sendCredentials=true', function (): void {
        $a = new SsrfOptions;
        $b = $a->withSendCredentials();
        expect($a->sendCredentials)->toBeFalse();
        expect($b->sendCredentials)->toBeTrue();
    });

    test('withSendCredentials(false) turns credentials off', function (): void {
        $a = (new SsrfOptions)->withSendCredentials();
        $b = $a->withSendCredentials(false);
        expect($b->sendCredentials)->toBeFalse();
    });

    test('withWhitelistIps replaces the list', function (): void {
        $a = (new SsrfOptions)->withWhitelistIps(['1.2.3.4']);
        $b = $a->withWhitelistIps(['5.6.7.8']);
        expect($a->whitelistIps)->toBe(['1.2.3.4']);
        expect($b->whitelistIps)->toBe(['5.6.7.8']);
    });

    test('withWhitelistPorts replaces the list', function (): void {
        $a = (new SsrfOptions)->withWhitelistPorts([80]);
        $b = $a->withWhitelistPorts([443]);
        expect($a->whitelistPorts)->toBe([80]);
        expect($b->whitelistPorts)->toBe([443]);
    });

    test('withWhitelistDomains replaces the list', function (): void {
        $a = (new SsrfOptions)->withWhitelistDomains(['a.com']);
        $b = $a->withWhitelistDomains(['b.com']);
        expect($a->whitelistDomains)->toBe(['a.com']);
        expect($b->whitelistDomains)->toBe(['b.com']);
    });

    test('withWhitelistSchemes replaces the list', function (): void {
        $a = (new SsrfOptions)->withWhitelistSchemes(['http']);
        $b = $a->withWhitelistSchemes(['https']);
        expect($a->whitelistSchemes)->toBe(['http']);
        expect($b->whitelistSchemes)->toBe(['https']);
    });

    test('withBlacklistIps replaces the list', function (): void {
        $a = (new SsrfOptions)->withBlacklistIps(['10.0.0.0/8']);
        $b = $a->withBlacklistIps(['192.168.0.0/16']);
        expect($a->blacklistIps)->toBe(['10.0.0.0/8']);
        expect($b->blacklistIps)->toBe(['192.168.0.0/16']);
    });

    test('withBlacklistPorts replaces the list', function (): void {
        $a = (new SsrfOptions)->withBlacklistPorts([22]);
        $b = $a->withBlacklistPorts([3306]);
        expect($a->blacklistPorts)->toBe([22]);
        expect($b->blacklistPorts)->toBe([3306]);
    });

    test('withBlacklistDomains replaces the list', function (): void {
        $a = (new SsrfOptions)->withBlacklistDomains(['evil.com']);
        $b = $a->withBlacklistDomains(['bad.net']);
        expect($a->blacklistDomains)->toBe(['evil.com']);
        expect($b->blacklistDomains)->toBe(['bad.net']);
    });

    test('withBlacklistSchemes replaces the list', function (): void {
        $a = (new SsrfOptions)->withBlacklistSchemes(['gopher']);
        $b = $a->withBlacklistSchemes(['ftp']);
        expect($a->blacklistSchemes)->toBe(['gopher']);
        expect($b->blacklistSchemes)->toBe(['ftp']);
    });
});

// ---------------------------------------------------------------------------
// Additive wither helpers
// ---------------------------------------------------------------------------

describe('additive wither helpers', function (): void {
    test('addBlacklistIp appends without duplication', function (): void {
        $opts = (new SsrfOptions)
            ->withBlacklistIps(['10.0.0.0/8'])
            ->addBlacklistIp('192.168.0.0/16')
            ->addBlacklistIp('10.0.0.0/8'); // duplicate

        expect($opts->blacklistIps)->toContain('10.0.0.0/8');
        expect($opts->blacklistIps)->toContain('192.168.0.0/16');
        expect(count(array_filter($opts->blacklistIps, fn ($v) => $v === '10.0.0.0/8')))->toBe(1);
    });

    test('addBlacklistIp accepts multiple variadic arguments', function (): void {
        $opts = (new SsrfOptions)
            ->withBlacklistIps([])
            ->addBlacklistIp('1.1.1.1', '2.2.2.2', '3.3.3.3');

        expect($opts->blacklistIps)->toBe(['1.1.1.1', '2.2.2.2', '3.3.3.3']);
    });

    test('addBlacklistDomain appends without duplication', function (): void {
        $opts = (new SsrfOptions)
            ->withBlacklistDomains(['evil.com'])
            ->addBlacklistDomain('bad.net')
            ->addBlacklistDomain('evil.com'); // duplicate

        expect($opts->blacklistDomains)->toContain('evil.com');
        expect($opts->blacklistDomains)->toContain('bad.net');
        expect(count(array_filter($opts->blacklistDomains, fn ($v) => $v === 'evil.com')))->toBe(1);
    });

    test('addWhitelistIp appends without duplication', function (): void {
        $opts = (new SsrfOptions)
            ->withWhitelistIps(['1.2.3.4'])
            ->addWhitelistIp('5.6.7.8')
            ->addWhitelistIp('1.2.3.4'); // duplicate

        expect($opts->whitelistIps)->toContain('1.2.3.4');
        expect($opts->whitelistIps)->toContain('5.6.7.8');
        expect(count(array_filter($opts->whitelistIps, fn ($v) => $v === '1.2.3.4')))->toBe(1);
    });

    test('addWhitelistDomain appends without duplication', function (): void {
        $opts = (new SsrfOptions)
            ->withWhitelistDomains(['trusted.com'])
            ->addWhitelistDomain('safe.org')
            ->addWhitelistDomain('trusted.com'); // duplicate

        expect($opts->whitelistDomains)->toContain('trusted.com');
        expect($opts->whitelistDomains)->toContain('safe.org');
        expect(count(array_filter($opts->whitelistDomains, fn ($v) => $v === 'trusted.com')))->toBe(1);
    });

    test('addWhitelistIp accepts multiple variadic arguments', function (): void {
        $opts = (new SsrfOptions)
            ->withWhitelistIps([])
            ->addWhitelistIp('1.1.1.1', '2.2.2.2');

        expect($opts->whitelistIps)->toBe(['1.1.1.1', '2.2.2.2']);
    });

    test('addWhitelistDomain accepts multiple variadic arguments', function (): void {
        $opts = (new SsrfOptions)
            ->withWhitelistDomains([])
            ->addWhitelistDomain('a.com', 'b.com');

        expect($opts->whitelistDomains)->toBe(['a.com', 'b.com']);
    });

    test('addBlacklistDomain accepts multiple variadic arguments', function (): void {
        $opts = (new SsrfOptions)
            ->withBlacklistDomains([])
            ->addBlacklistDomain('evil.com', 'bad.net');

        expect($opts->blacklistDomains)->toBe(['evil.com', 'bad.net']);
    });
});
