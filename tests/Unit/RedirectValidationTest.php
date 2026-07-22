<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Securized\Ssrf\Http\Middleware\SsrfProtectionMiddleware;

function redirectingClient(string $location): Client
{
    $mock = new MockHandler([
        new Response(302, ['Location' => $location]),
        new Response(200, [], 'reached the redirect target'),
    ]);

    $stack = HandlerStack::create($mock);
    $stack->push(SsrfProtectionMiddleware::make());

    return new Client(['handler' => $stack]);
}

test('a redirect to a blacklisted IP is blocked', function (): void {
    $client = redirectingClient('http://169.254.169.254/latest/meta-data/');

    expect(fn () => $client->get('http://example.com/redirector'))
        ->toThrow(RequestException::class, '169.254.0.0/16');
});

test('a redirect to loopback is blocked', function (): void {
    $client = redirectingClient('http://127.0.0.1:6379/');

    expect(fn () => $client->get('http://example.com/redirector'))
        ->toThrow(RequestException::class);
});

test('a redirect to a permitted host is followed', function (): void {
    $client = redirectingClient('http://example.com/final');

    expect((string) $client->get('http://example.com/redirector')->getBody())
        ->toBe('reached the redirect target');
});
