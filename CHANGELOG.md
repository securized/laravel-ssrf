# Changelog

All notable changes to `securized/laravel-ssrf` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 1.1.0 - 2026-11-24

### Changed

- DNS pinning in the HTTP client middleware now uses `CURLOPT_RESOLVE` instead of replacing the hostname in the request URL, so TLS SNI and certificate validation keep working against the original hostname ([#2](https://github.com/securized/laravel-ssrf/issues/2)).
- DNS pinning now also holds for requests sent through a proxy (including a SOCKS pre-proxy), for IDN hostnames and for non-curl handlers the middleware can see, pins every validated address instead of the first, and no longer leaves entries behind on a reused curl handle.

### Added

- `SsrfProtectionMiddleware::REWRITE_OPTION`, a Guzzle request option that pins by replacing the URL host, for clients built with a handler that ignores curl options.

### Fixed

- With `whitelist_ips`, pinning and `Ssrf::safeUrl()` could pick an address that was not whitelisted when a host resolved to both whitelisted and other addresses.
- The `Host` header lost a non-default port when the hostname in the URL was replaced with the IP.
- A pinned request to a host exempted by `no_proxy` was sent to the proxy anyway once the URL carried the IP.
- An IDN host was sent as raw UTF-8 in the `Host` header when the hostname in the URL was replaced with the IP.

### Security

- Hosts containing a percent-escape or other characters that are not valid in a hostname are now rejected. curl decodes the host before resolving it, so `%61.example.com` was validated under one name and fetched under another.
- Hosts are now validated under the name curl looks up: IDN hosts are converted to punycode and a trailing dot is dropped before the domain lists and DNS are consulted. Previously `ｅxample.com` and `example.com.` skipped a `blacklist_domains` entry for `example.com`. Non-ASCII hosts are rejected when the intl extension is missing.
- A bracketed host that is not an IPv6 address is now rejected.
- With `whitelist_ips` set, a host is now rejected unless every address it resolves to is whitelisted, except for requests that are actually pinned (the middleware and `Ssrf::safeUrl()` with `pin_dns` on). Previously one whitelisted address was enough, while curl could connect to any of the others.
- Numeric hosts that are not dotted-decimal IPv4 (`0177.0.0.1`, `0x7f000001`, `2130706433`, `127.1`, `127.0.0.1.`) are now rejected before any DNS lookup. Previously they were looked up, so a resolver that answered for one could get the URL approved while curl connected to the address it encodes.

## 1.0.0 - 2026-07-22

Initial release.
