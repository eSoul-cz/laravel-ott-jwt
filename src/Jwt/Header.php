<?php

declare(strict_types=1);

namespace Esoul\OttJwt\Jwt;

use Esoul\OttJwt\Jwt\Exceptions\InvalidJWTException;
use JsonSerializable;
use Stringable;

final readonly class Header implements JsonSerializable, Stringable
{
    use Encodable;

    public function __construct(
        public string $alg = 'HS256',
        public string $typ = 'JWT',
    ) {}

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return [
            'alg' => $this->alg,
            'typ' => $this->typ,
        ];
    }

    /**
     * @param  array{alg?:string,typ?:string}  $data
     */
    protected static function fromDecodedData(array $data): Header
    {
        if (! isset($data['alg'])) {
            throw new InvalidJWTException('Missing "alg" in JWT header');
        }
        if (! isset($data['typ'])) {
            throw new InvalidJWTException('Missing "typ" in JWT header');
        }

        return new Header(
            alg: $data['alg'],
            typ: $data['typ'],
        );
    }
}
