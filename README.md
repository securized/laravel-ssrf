# Laravel SSRF Prevention

[![Latest Version on Packagist](https://img.shields.io/packagist/v/securized/laravel-ssrf.svg?style=flat-square)](https://packagist.org/packages/securized/laravel-ssrf)
[![Tests](https://img.shields.io/github/actions/workflow/status/securized/laravel-ssrf/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/securized/laravel-ssrf/actions/workflows/tests.yml)
[![Quality](https://img.shields.io/github/actions/workflow/status/securized/laravel-ssrf/quality.yml?branch=main&label=quality&style=flat-square)](https://github.com/securized/laravel-ssrf/actions/workflows/quality.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/securized/laravel-ssrf.svg?style=flat-square)](https://packagist.org/packages/securized/laravel-ssrf)

SSRF (Server-Side Request Forgery) prevention for Laravel. Protect `Http::`, raw Guzzle, and user-supplied URLs from being weaponised to reach internal infrastructure, cloud metadata endpoints, or private networks.

## The problem

Fetching a user-supplied URL is a normal thing to do — webhooks, link previews, avatar imports, "import from URL" buttons. The code usually looks like this:

```php
$response = Http::get($request->input('webhook_url'));
```

Your server will happily fetch whatever it's pointed at, from a network position your users don't have. So an attacker submits:

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

On unpatched EC2 (IMDSv1), that returns your instance's IAM credentials. The same trick reaches `http://localhost:6379` (Redis), your internal admin panel, or a Kubernetes API on a private subnet — anything your server can route to but the internet can't.

Blocking this properly is harder than it looks. `127.0.0.1` is also `http://0177.0.0.1/`, `http://2130706433/`, and `http://[::1]/`. A hostname that resolves to a public IP when you check it can resolve to `127.0.0.1` a second later when Guzzle connects. This package handles those cases and validates every URL before the request leaves your application.

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

// Returns array{url: string, host: string, ips: list<string>, pinned: bool}
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

Domain entries are literal hostnames with `*` as a wildcard, matched
case-insensitively:

```php
'whitelist' => [
    'domains' => [
        'api.example.com',      // exact host
        '*.trusted.com',        // any subdomain (not the bare apex)
    ],
],
```

Dots are literal, so a pattern never matches more hosts than it appears to —
`api.example.com` matches that host and nothing else. Regex syntax is not
supported; characters like `.` and `(` are matched literally.

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

## What this does not protect against

Worth knowing before you rely on it:

- **Second-order requests are your responsibility.** Redirects *are* covered — Guzzle re-enters the middleware for each hop, so a `302` to `http://169.254.169.254/` is blocked (there are tests for this). But if you fetch a page, parse a URL out of the body, and request it yourself, that second request needs its own validation.
- **TOCTOU without DNS pinning.** With `pin_dns` disabled, the hostname is resolved once for validation and again by Guzzle when it connects. An attacker controlling the DNS response can return a public IP for the first lookup and a private one for the second. Enable `pin_dns` to close this.
- **Blocked hosts are still distinguishable.** Timing and error differences let an attacker infer which internal hosts exist. This is a port scan with a very narrow oracle, not data exfiltration, but it is not nothing.
- **The blacklist covers documented ranges, not your network.** If your internal services live on public IPs, add them to the blacklist yourself — nothing here can infer that.

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

## Security Vulnerabilities

If you find a security issue in this package, please email `root@securized.dev` rather than opening a public issue.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
