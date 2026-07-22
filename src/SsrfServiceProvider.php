<?php

declare(strict_types=1);

namespace Securized\Ssrf;

use Illuminate\Support\Facades\Http;
use Securized\Ssrf\Http\Middleware\SsrfProtectionMiddleware;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class SsrfServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package->name('ssrf')->hasConfigFile();
    }

    public function packageRegistered(): void
    {
        $this->app->bind(SsrfOptions::class, fn ($app): SsrfOptions => SsrfOptions::fromConfig($app['config']->get('ssrf', []))
        );

        $this->app->bind(SsrfValidator::class, fn ($app): SsrfValidator => new SsrfValidator($app->make(SsrfOptions::class))
        );
    }

    public function packageBooted(): void
    {
        Http::macro('withSsrfProtection', function (?SsrfOptions $options = null) {
            /** @var \Illuminate\Http\Client\PendingRequest $this */
            $validator = $options ? new SsrfValidator($options) : app(SsrfValidator::class);

            return $this->withMiddleware((new SsrfProtectionMiddleware($validator))->handler());
        });

        Http::macro('ssrf', function (?SsrfOptions $options = null) {
            /** @var \Illuminate\Http\Client\PendingRequest $this */
            // @phpstan-ignore-next-line method.notFound (registered above via Http::macro)
            return $this->withSsrfProtection($options);
        });

        if (config('ssrf.auto_protect', false)) {
            Http::globalMiddleware((new SsrfProtectionMiddleware(app(SsrfValidator::class)))->handler());
        }
    }
}
