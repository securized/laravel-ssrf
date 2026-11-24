# Changelog

All notable changes to `securized/laravel-ssrf` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

Initial release.

### Changed

- DNS pinning in the HTTP client middleware now uses `CURLOPT_RESOLVE` instead of replacing the hostname in the request URL, so TLS SNI and certificate validation keep working against the original hostname ([#2](https://github.com/securized/laravel-ssrf/issues/2)).
- DNS pinning now also holds for requests sent through a proxy and for IDN hostnames, pins every validated address instead of the first, and no longer leaves entries behind on a reused curl handle.

### Fixed

- With `whitelist_ips`, pinning and `Ssrf::safeUrl()` could pick an address that was not whitelisted when a host resolved to both whitelisted and other addresses.
- The `Host` header lost a non-default port when the hostname in the URL was replaced with the IP.

### Security

- Numeric hosts that are not dotted-decimal IPv4 (`0177.0.0.1`, `0x7f000001`, `2130706433`, `127.1`, `127.0.0.1.`) are now rejected before any DNS lookup. Previously they were looked up, so a resolver that answered for one could get the URL approved while curl connected to the address it encodes.
