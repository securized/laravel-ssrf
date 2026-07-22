<?php

declare(strict_types=1);

namespace Securized\Ssrf\Facades;

use Illuminate\Support\Facades\Facade;
use Securized\Ssrf\SsrfOptions;
use Securized\Ssrf\SsrfValidator;

/**
 * @method static array{url: string, host: string, ips: list<string>, pinned: bool} validate(string $url)
 * @method static bool   isSafe(string $url)
 * @method static string safeUrl(string $url)
 *
 * @see \Securized\Ssrf\SsrfValidator
 */
class Ssrf extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return SsrfValidator::class;
    }
}
