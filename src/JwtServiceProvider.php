<?php

declare(strict_types=1);

namespace Esoul\OttJwt;

use Esoul\OttJwt\Services\TokenParser;
use Illuminate\Contracts\Foundation\Application;
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
}
