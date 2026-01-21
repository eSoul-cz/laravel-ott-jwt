<?php

declare(strict_types=1);

namespace Esoul\OttJwt\Facades;

use Esoul\OttJwt\Jwt\Exceptions\InvalidJWTException;
use Esoul\OttJwt\Jwt\Token;
use Esoul\OttJwt\Services\TokenParser;
use Illuminate\Support\Facades\Facade;

/**
 * @method static Token parse(string $data)
 * @method static bool validateHeader(Token $token)
 * @method static bool validateExpiration(Token $token)
 * @method static bool validateSignature(Token $token)
 * @method static Token parseAndValidate(string $data)
 *
 * @throws InvalidJWTException
 */
class JwtParser extends Facade
{
    /**
     * @return class-string<TokenParser>
     */
    protected static function getFacadeAccessor(): string
    {
        return TokenParser::class;
    }
}
