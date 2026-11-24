# Changelog

All notable changes to `securized/laravel-ssrf` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

Initial release.

### Security

- Numeric hosts that are not dotted-decimal IPv4 (`0177.0.0.1`, `0x7f000001`, `2130706433`, `127.1`, `127.0.0.1.`) are now rejected before any DNS lookup. Previously they were looked up, so a resolver that answered for one could get the URL approved while curl connected to the address it encodes.
