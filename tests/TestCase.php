<?php

declare(strict_types=1);

namespace Securized\Ssrf\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Securized\Ssrf\SsrfServiceProvider;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            SsrfServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        config()->set('ssrf', require __DIR__ . '/../config/ssrf.php');
    }
}
