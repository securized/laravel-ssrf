# Laravel SSRF Prevention

[![Latest Version on Packagist](https://img.shields.io/packagist/v/securized/laravel-ssrf.svg?style=flat-square)](https://packagist.org/packages/securized/laravel-ssrf)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/securized/laravel-ssrf/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/securized/laravel-ssrf/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/securized/laravel-ssrf/fix-php-code-style-issues.yml?branch=main&label=code%20style&style=flat-square)](https://github.com/securized/laravel-ssrf/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/securized/laravel-ssrf.svg?style=flat-square)](https://packagist.org/packages/securized/laravel-ssrf)

SSRF (Server-Side Request Forgery) prevention for Laravel. Protect `Http::`, raw Guzzle, and user-supplied URLs from being weaponised to reach internal infrastructure, cloud metadata endpoints, or private networks.

Server-side requests are a common and useful pattern — webhooks, link previews, external API calls — but allowing user-controlled URLs without validation lets an attacker redirect your server to `http://169.254.169.254/` (AWS metadata), internal services, or arbitrary internal hosts. This package validates every URL before the request leaves your application.

## Installation

```bash
composer require securized/laravel-ssrf
```

Publish the config file:

```bash
php artisan vendor:publish --tag="ssrf-config"
```

## Quick Start

```php
use Illuminate\Support\Facades\Http;

// Wrap any Http:: call with ->ssrf() to enable protection
Http::ssrf()->get($userSuppliedUrl);
Http::ssrf()->post($webhookUrl, $payload);
```

That's it. Requests to private IPs, localhost, link-local addresses (including cloud metadata endpoints), and non-HTTP(S) schemes are blocked out of the box.

## Features

- **Laravel HTTP Client macro** — `Http::ssrf()` and `Http::withSsrfProtection()`
- **Raw Guzzle middleware** — drop into any `HandlerStack`
- **Validation rule** — `new SsrfSafeUrl()` for form/API input validation
- **Facade** — `Ssrf::validate($url)`, `Ssrf::isSafe($url)`, `Ssrf::safeUrl($url)`
- **IPv4 + IPv6** — blocks private ranges for both address families
- **DNS pinning** — prevents DNS rebinding attacks
- **Configurable** — whitelist/blacklist for IPs, ports, domains, and schemes
- **Immutable options** — safe in long-running processes (Octane, RoadRunner)

## Usage

### Laravel HTTP Client

The `ssrf()` and `withSsrfProtection()` macros return a `PendingRequest` and chain normally with all other HTTP client methods:

```php
use Illuminate\Support\Facades\Http;

// Protect a single request
$response = Http::ssrf()->get($userUrl);

// Chain with other options
$response = Http::ssrf()
    ->withHeaders(['Accept' => 'application/json'])
    ->timeout(10)
    ->get($userUrl);

// Both macros are identical
Http::withSsrfProtection()->post($webhookUrl, $data);
```

Blocked requests throw a `\GuzzleHttp\Exception\RequestException` (the same exception Guzzle throws for failed requests), so your existing error handling works without changes.

### Global Protection

To protect every outgoing `Http::` request automatically, set `auto_protect` in your `.env`:

```env
SSRF_AUTO_PROTECT=true
```

Or in `config/ssrf.php`:

```php
'auto_protect' => true,
```

### Raw Guzzle

Use the static factory to add SSRF protection to any Guzzle client without the Laravel container:

```php
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Securized\Ssrf\Http\Middleware\SsrfProtectionMiddleware;

$stack = HandlerStack::create();
$stack->push(SsrfProtectionMiddleware::make());

$client = new Client(['handler' => $stack]);
$response = $client->get($userUrl);
```

### Validation Rule

Validate user-supplied URLs in form requests or controllers:

```php
use Securized\Ssrf\Rules\SsrfSafeUrl;

$request->validate([
    'webhook_url' => ['required', 'url', new SsrfSafeUrl()],
    'preview_url' => ['required', 'url', new SsrfSafeUrl()],
]);
```

The validation error message deliberately does not expose internal network details to end users.

### Facade

```php
use Securized\Ssrf\Facades\Ssrf;

// Returns array{url: string, host: string, ips: list<string>}
// Throws SsrfException on failure.
$result = Ssrf::validate($url);

// Returns the validated URL string.
// When pin_dns is enabled, the host is replaced with the resolved IP.
// Always use this value for the actual request, not the original $url.
// Throws SsrfException on failure.
$safeUrl = Ssrf::safeUrl($url);

// Returns true/false — never throws.
if (!Ssrf::isSafe($url)) {
    abort(422, 'URL is not permitted.');
}
```

## Configuration

After publishing, edit `config/ssrf.php`:

```php
return [

    // Apply SSRF protection to all Http:: requests globally.
    'auto_protect' => env('SSRF_AUTO_PROTECT', false),

    // Allow credentials (user:pass@host) in URLs. Disabled by default.
    'send_credentials' => false,

    // Replace hostname with resolved IP before sending the request.
    // Prevents DNS rebinding attacks. See "DNS Pinning" below.
    'pin_dns' => false,

    'whitelist' => [
        'ips'     => [],               // CIDR ranges or exact IPs
        'ports'   => [80, 443, 8080],  // Allowed ports (empty = allow all)
        'domains' => [],               // Regex patterns (empty = allow all)
        'schemes' => ['http', 'https'],
    ],

    'blacklist' => [
        'ips' => [
            // RFC 1918 private ranges
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
            // Loopback
            '127.0.0.0/8',
            // Link-local (cloud metadata: AWS, GCP, Azure)
            '169.254.0.0/16',
            // ... and more (see config/ssrf.php for the full list)
        ],
        'ports'   => [],
        'domains' => [],
        'schemes' => [],
    ],
];
```

### Whitelist semantics

An **empty whitelist** for a type means "allow all" (subject to the blacklist). A **non-empty whitelist** means only the listed values are permitted. The blacklist always takes precedence.

### Domain patterns

Domain entries support regex syntax, matched case-insensitively:

```php
'whitelist' => [
    'domains' => [
        'api\.example\.com',      // exact domain
        '(.*)\.trusted\.com',     // any subdomain
    ],
],
```

> **Escape your dots.** Entries are regular expressions, so an unescaped `.`
> matches any character — `api.example.com` would also match `apiXexample.com`.
> Always write `api\.example\.com`.

A malformed pattern throws `InvalidDomainException` rather than silently failing
to match, so a typo in a blacklist can never quietly allow a host through.

### IP ranges

IP entries support CIDR notation for both IPv4 and IPv6:

```php
'blacklist' => [
    'ips' => [
        '10.0.0.0/8',   // IPv4 range
        'fc00::/7',     // IPv6 unique local
    ],
],
```

## Per-Request Options

Override the global config for a single request using `SsrfOptions`:

```php
use Securized\Ssrf\SsrfOptions;

// Build from config and customise
$options = SsrfOptions::fromConfig(config('ssrf'))
    ->withPinDns()
    ->withWhitelistSchemes(['https'])  // HTTPS only for this request
    ->addBlacklistIp('203.0.113.0/24');

Http::ssrf($options)->get($url);

// Also works with the validation rule
new SsrfSafeUrl($options)
```

`SsrfOptions` is immutable — each method returns a new instance, so customising per-request never affects shared state.

## DNS Pinning

DNS rebinding is an attack where a hostname initially resolves to a public IP (passing validation) but then re-resolves to a private IP for the actual request. Enabling `pin_dns` prevents this by resolving the hostname once, validating the IP, and then replacing the hostname in the URL with that IP for the actual request. The original `Host` header is preserved.

```php
// In config/ssrf.php
'pin_dns' => true,

// Or per-request
Http::ssrf(SsrfOptions::fromConfig(config('ssrf'))->withPinDns())->get($url);
```

Note: DNS pinning may affect SSL certificate validation in some configurations.

## Exception Hierarchy

All SSRF exceptions extend `\Securized\Ssrf\Exceptions\SsrfException` (itself a `RuntimeException`):

```
SsrfException
└── InvalidUrlException      — URL cannot be parsed, is empty, or contains credentials
    ├── InvalidSchemeException  — scheme not permitted (e.g. file://, gopher://)
    ├── InvalidPortException    — port not permitted
    ├── InvalidDomainException  — hostname not permitted or does not resolve
    └── InvalidIpException      — resolved IP matches a blacklisted range
```

Catch `SsrfException` to handle any SSRF failure, or catch specific subclasses for fine-grained handling:

```php
use Securized\Ssrf\Exceptions\InvalidIpException;
use Securized\Ssrf\Exceptions\SsrfException;
use Securized\Ssrf\Facades\Ssrf;

try {
    $safeUrl = Ssrf::safeUrl($userUrl);
} catch (InvalidIpException $e) {
    // Resolved to a private IP
} catch (SsrfException $e) {
    // Any other validation failure
}
```

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
