<?php

declare(strict_types=1);

namespace Esoul\OttJwt\Services;

use DateTimeImmutable;
use Esoul\OttJwt\Jwt\Exceptions\InvalidJWTException;
use Esoul\OttJwt\Jwt\Token;
use InvalidArgumentException;
use JsonException;
use RuntimeException;
use SensitiveParameter;

final readonly class TokenParser
{
    public function __construct(
        #[SensitiveParameter]
        private string $secret,
    ) {
        if (empty($secret)) {
            throw new InvalidArgumentException('JWT secret must not be empty');
        }
    }

    public function parse(string $data): Token
    {
        return Token::decode($data);
    }

    public function validateHeader(Token $token): bool
    {
        return $token->header->alg === 'HS256' && $token->header->typ === 'JWT';
    }

    public function validateExpiration(Token $token): bool
    {
        return $token->payload->exp >= new DateTimeImmutable;
    }

    public function validateSignature(Token $token): bool
    {
        try {
            $expectedSignature = hash_hmac(
                'sha256',
                $token->header->encode().'.'.$token->payload->encode(),
                $this->secret,
                true
            );
        } catch (JsonException $e) {
            throw new RuntimeException('Error encoding JWT header or payload for signature validation: '.$e->getMessage(), previous: $e);
        }

        return hash_equals($expectedSignature, $token->signature);
    }

    /**
     * @throws InvalidJWTException
     */
    public function parseAndValidate(string $data): Token
    {
        // Decode the JWT token
        $token = $this->parse($data);

        // Validate the signature
        if (! $this->validateSignature($token)) {
            throw new InvalidJWTException('Invalid JWT signature');
        }

        // Validate the header
        if (! $this->validateHeader($token)) {
            throw new InvalidJWTException('Invalid JWT header');
        }

        // Validate the payload
        if (! $this->validateExpiration($token)) {
            throw new InvalidJWTException('JWT token has expired');
        }

        // Return the validated token
        return $token;
    }
}
