<?php

declare(strict_types=1);

namespace Esoul\OttJwt\Services\Auth;

use Esoul\OttJwt\Auth\JwtUser;
use Esoul\OttJwt\Facades\JwtParser;
use Esoul\OttJwt\Jwt\Exceptions\InvalidJWTException;
use Esoul\OttJwt\Jwt\Token;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;

class JwtGuard implements Guard
{
    use GuardHelpers;

    private(set) ?Token $token = null;

    public function __construct(
        public readonly string $name,
        protected ?Request $request = null,
    ) {}

    public function user(): ?Authenticatable
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $request = $this->getRequest();
        /** @var string|string[] $token */
        $token = $request?->header('Authorization', '') ?? '';
        if (!is_string($token)) {
            $token = array_first($token);
            assert(is_string($token));
        }
        if (empty($token) || ! str_starts_with($token, 'Bearer ')) {
            return null;
        }

        $token = substr($token, 7); // Remove 'Bearer ' prefix
        if ($this->validate(['token' => $token])) {
            return $this->user;
        }

        return null;
    }

    /**
     * @param  array{token?:string}  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        if (! isset($credentials['token'])) {
            return false;
        }
        try {
            $token = JwtParser::parseAndValidate($credentials['token']);
            /** @phpstan-ignore catch.neverThrown */
        } catch (InvalidJWTException) {
            return false;
        }

        $user = new JwtUser($token);

        $this->token = $token;
        $this->setUser($user);

        return true;
    }

    public function forgetUser(): static
    {
        $this->token = null;
        $this->user = null;

        return $this;
    }

    public function setRequest(?Request $request): JwtGuard
    {
        $this->request = $request;

        return $this;
    }

    protected function getRequest(): ?Request
    {
        /** @phpstan-ignore return.type */
        return $this->request ?? app('request');
    }
}
