<?php

declare(strict_types=1);

namespace Esoul\OttJwt;

use Esoul\OttJwt\Services\Auth\JwtGuard;
use Esoul\OttJwt\Services\TokenParser;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class JwtServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('ott-jwt')
            ->hasConfigFile('jwt');
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(
            TokenParser::class,
            static fn (Application $app) => new TokenParser(
                /** @phpstan-ignore argument.type */
                config('jwt.secret', ''),
            ),
        );
    }

    public function packageBooted(): void
    {
        Auth::extend(
            'jwt',
            static fn (Application $app, string $name, array $config) => new JwtGuard(name: $name)
        );
    }
}
