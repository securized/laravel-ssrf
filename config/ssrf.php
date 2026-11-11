<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Auto-protect all HTTP Client requests
    |--------------------------------------------------------------------------
    |
    | When true, SSRF protection is applied globally to every Http::...
    | request via Http::globalMiddleware(). Defaults to false so that
    | installing the package does not break apps that legitimately call
    | internal services (e.g. microservices architectures).
    |
    */
    'auto_protect' => env('SSRF_AUTO_PROTECT', false),

    /*
    |--------------------------------------------------------------------------
    | Send Credentials
    |--------------------------------------------------------------------------
    |
    | Whether URLs containing user:password@ credentials are permitted.
    | Defaults to false — credentials embedded in URLs are blocked.
    |
    */
    'send_credentials' => false,

    /*
    |--------------------------------------------------------------------------
    | Pin DNS
    |--------------------------------------------------------------------------
    |
    | When true, outgoing requests connect to the first resolved IP address
    | via CURLOPT_RESOLVE, preventing DNS rebinding attacks. The URL keeps
    | its hostname, so the Host header, SNI and certificate checks are
    | unaffected. Without curl, the hostname is replaced by the IP instead.
    |
    */
    'pin_dns' => false,

    /*
    |--------------------------------------------------------------------------
    | Whitelists
    |--------------------------------------------------------------------------
    |
    | Only values in a non-empty whitelist are permitted for that type.
    | An empty whitelist means "allow all" (the blacklist still applies).
    |
    */
    'whitelist' => [

        // IP addresses or CIDR ranges that are explicitly allowed.
        'ips' => [],

        // Ports that outgoing requests may target.
        'ports' => [80, 443, 8080],

        // Hostnames that are explicitly allowed. Dots are literal and "*" is a
        // wildcard, e.g. 'api.example.com' or '*.example.com'.
        'domains' => [],

        // URL schemes that are permitted.
        'schemes' => ['http', 'https'],

    ],

    /*
    |--------------------------------------------------------------------------
    | Blacklists
    |--------------------------------------------------------------------------
    |
    | Values in a blacklist are always rejected, even if also whitelisted.
    | The default IP blacklist covers RFC 1918 private ranges, loopback,
    | link-local (including cloud metadata endpoints like 169.254.169.254),
    | documentation ranges, and multicast/reserved space — for both IPv4
    | and IPv6.
    |
    */
    'blacklist' => [

        'ips' => [
            // IPv4
            '0.0.0.0/8',       // "This" network
            '10.0.0.0/8',      // RFC 1918 private
            '100.64.0.0/10',   // Shared address space (RFC 6598)
            '127.0.0.0/8',     // Loopback
            '169.254.0.0/16',  // Link-local (AWS/GCP/Azure metadata)
            '172.16.0.0/12',   // RFC 1918 private
            '192.0.0.0/29',    // IETF Protocol Assignments
            '192.0.2.0/24',    // TEST-NET-1 (documentation)
            '192.88.99.0/24',  // 6to4 Relay Anycast (deprecated)
            '192.168.0.0/16',  // RFC 1918 private
            '198.18.0.0/15',   // Network benchmarking
            '198.51.100.0/24', // TEST-NET-2 (documentation)
            '203.0.113.0/24',  // TEST-NET-3 (documentation)
            '224.0.0.0/4',     // Multicast
            '240.0.0.0/4',     // Reserved

            // IPv6
            '::/128',           // Unspecified address
            '::1/128',          // Loopback
            '::ffff:0:0/96',    // IPv4-mapped IPv6 (blocks ::ffff:127.0.0.1 etc.)
            '100::/64',         // Discard prefix (RFC 6666)
            '2001:db8::/32',    // Documentation range
            '2002::/16',        // 6to4 (can embed private IPv4)
            'fc00::/7',         // Unique local (RFC 4193, includes fd00::/8)
            'fe80::/10',        // Link-local
            'ff00::/8',         // Multicast
        ],

        'ports' => [],

        'domains' => [],

        'schemes' => [],

    ],

];
