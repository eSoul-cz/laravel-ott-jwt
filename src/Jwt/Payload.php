<?php

declare(strict_types=1);

namespace Esoul\OttJwt\Jwt;

use DateMalformedStringException;
use DateTimeImmutable;
use DateTimeInterface;
use Esoul\OttJwt\Jwt\Exceptions\InvalidJWTException;
use JsonSerializable;
use Stringable;

final readonly class Payload implements JsonSerializable, Stringable
{
    use Encodable;

    /**
     * @param  int  $sub  Subject (User ID)
     * @param  DateTimeInterface  $iat  Issued at
     * @param  DateTimeInterface  $exp  Expiration time
     * @param  array<'client'|numeric, string[]>  $cap  Capabilities (identifiers)
     */
    public function __construct(
        public int $sub,
        public string $name,
        public string $email,
        public int $ins,
        public DateTimeInterface $iat,
        public DateTimeInterface $exp,
        public array $cap = [],
    ) {}

    /**
     * @param  array{
     *     sub?:numeric,
     *     name?:string,
     *     email?:string,
     *     ins?:numeric,
     *     iat?:string,
     *     exp?:string,
     *     cap?:array<'client'|numeric, string[]>
     * }  $data
     */
    protected static function fromDecodedData(array $data): Payload
    {
        if (! isset($data['sub'], $data['name'], $data['email'], $data['ins'], $data['iat'], $data['exp'])) {
            throw new InvalidJWTException('Missing required fields in JWT payload');
        }
        try {
            $data['iat'] = is_numeric($data['iat']) ? DateTimeImmutable::createFromTimestamp((int) $data['iat']) : new DateTimeImmutable($data['iat']);
            $data['exp'] = is_numeric($data['exp']) ? DateTimeImmutable::createFromTimestamp((int) $data['exp']) : new DateTimeImmutable($data['exp']);
        } catch (DateMalformedStringException $e) {
            throw new InvalidJWTException('Invalid date format in JWT payload: '.$e->getMessage(), previous: $e);
        }

        return new Payload(
            sub: (int) $data['sub'],
            name: $data['name'],
            email: $data['email'],
            ins: (int) $data['ins'],
            iat: $data['iat'],
            exp: $data['exp'],
            cap: $data['cap'] ?? []
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'sub' => $this->sub,
            'name' => $this->name,
            'email' => $this->email,
            'ins' => $this->ins,
            'iat' => $this->iat->getTimestamp(),
            'exp' => $this->exp->getTimestamp(),
            'cap' => $this->cap,
        ];
    }
}
