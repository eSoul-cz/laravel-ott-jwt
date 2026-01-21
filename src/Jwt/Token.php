<?php

declare(strict_types=1);

namespace Esoul\OttJwt\Jwt;

use Esoul\OttJwt\Jwt\Exceptions\InvalidJWTException;
use JsonException;
use JsonSerializable;
use Stringable;

final readonly class Token implements JsonSerializable, Stringable
{
    use Encodable;

    public function __construct(
        public Header $header,
        public Payload $payload,
        public string $signature,
    ) {}

    public static function decode(string $data): self
    {
        $parts = explode('.', $data);
        if (count($parts) !== 3) {
            throw new InvalidJWTException('Invalid JWT format');
        }

        $header = Header::decode($parts[0]);
        $payload = Payload::decode($parts[1]);
        $signature = self::base64UrlDecode($parts[2]);

        if ($signature === false) {
            throw new InvalidJWTException('Cannot decode JWT signature');
        }

        return new Token($header, $payload, $signature);
    }

    public static function base64UrlDecode(string $data): string|false
    {
        $data .= str_repeat('=', (4 - strlen($data) % 4) % 4); // Add padding

        return base64_decode(
            str_replace(
                ['-', '_'],
                ['+', '/'],
                $data
            ),
            true
        );
    }

    /**
     * @throws JsonException
     */
    public function jsonSerialize(): string
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
        $header = $this->header->encode();
        $payload = $this->payload->encode();
        $signature = self::base64UrlEncode($this->signature);

        return "$header.$payload.$signature";
    }

    public static function base64UrlEncode(string $data): string
    {
        return str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode($data)
        );
    }
}
