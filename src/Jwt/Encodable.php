<?php

declare(strict_types=1);

namespace Esoul\OttJwt\Jwt;

use Esoul\OttJwt\Jwt\Exceptions\InvalidJWTException;
use JsonException;
use Throwable;

trait Encodable
{
    /**
     * Decode a JWT string into an instance of the class.
     *
     * @throws InvalidJWTException
     */
    public static function decode(string $data): static
    {
        try {
            /** @var array<string,mixed> $decodedData */
            $decodedData = json_decode(Token::base64UrlDecode($data) ?: '', true, 512, JSON_THROW_ON_ERROR);

            // @phpstan-ignore argument.type
            return static::fromDecodedData($decodedData);
        } catch (Throwable $e) {
            throw new InvalidJWTException('Cannot decode '.static::class.': '.$e->getMessage(), previous: $e);
        }
    }

    /**
     * @param  array<string,mixed>  $data
     */
    protected static function fromDecodedData(array $data): static
    {
        // @phpstan-ignore argument.type
        return new static(...$data);
    }

    /**
     * @throws JsonException
     */
    public function __toString(): string
    {
        return $this->encode();
    }

    /**
     * Encode the JWT into a string format.
     *
     * @throws JsonException
     */
    public function encode(): string
    {
        return Token::base64UrlEncode(json_encode($this, JSON_THROW_ON_ERROR));
    }
}
