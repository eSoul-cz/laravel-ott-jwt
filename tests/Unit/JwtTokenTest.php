<?php

declare(strict_types=1);

namespace Esoul\OttJwt\Tests\Unit;

use DateTimeImmutable;
use Esoul\OttJwt\Jwt\Exceptions\InvalidJWTException;
use Esoul\OttJwt\Jwt\Header;
use Esoul\OttJwt\Jwt\Payload;
use Esoul\OttJwt\Jwt\Token;
use Esoul\OttJwt\Services\TokenParser;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;

class JwtTokenTest extends TestCase
{
    private const string SECRET = 'ae0c0279753c20e3f79c95361364a5f504247bac3c857c861186189dbc386938';

    private TokenParser $tokenParser;

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function getInvalidDecodeData(): iterable
    {
        yield 'regular string' => ['invalid.token.format'];
        yield 'string header' => ['header.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJnc3Rva2VzQGV4YW1wbGUuY29tIiwiaW5zIjo0LCJpYXQiOiIyMDI1LTA3LTE3VDExOjU0OjQ1KzAwOjAwIiwiZXhwIjoiMjEyNS0wNy0xN1QxMjo1NDo0NSswMDowMCJ9.aa6clBsfHp6XeX1KkDKEYe0Krz7zqJYRCxf1sPHRRbs'];
        yield 'string payload' => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.aa6clBsfHp6XeX1KkDKEYe0Krz7zqJYRCxf1sPHRRbs'];
        yield 'string signature' => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJnc3Rva2VzQGV4YW1wbGUuY29tIiwiaW5zIjo0LCJpYXQiOiIyMDI1LTA3LTE3VDExOjU0OjQ1KzAwOjAwIiwiZXhwIjoiMjEyNS0wNy0xN1QxMjo1NDo0NSswMDowMCJ9.signature'];
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function getInvalidFormats(): iterable
    {
        yield 'empty string' => [''];
        yield 'only header' => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9']; // Missing payload and signature
        yield 'header and payload' => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJnc3Rva2VzQGV4YW1wbGUuY29tIiwiaW5zIjo0LCJpYXQiOiIyMDI1LTA3LTE3VDExOjU0OjQ1KzAwOjAwIiwiZXhwIjoiMjEyNS0wNy0xN1QxMjo1NDo0NSswMDowMCJ9']; // Missing signature
        yield 'extra parts' => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJnc3Rva2VzQGV4YW1wbGUuY29tIiwiaW5zIjo0LCJpYXQiOiIyMDI1LTA3LTE3VDExOjU0OjQ1KzAwOjAwIiwiZXhwIjoiMjEyNS0wNy0xN1QxMjo1NDo0NSswMDowMCJ9.extra.part'];
    }

    public function test_decode(): void
    {
        // Expiration is hardcoded to the year 2125, so it should be valid for a while...
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJnc3Rva2VzQGV4YW1wbGUuY29tIiwiaW5zIjoxLCJpYXQiOjE3NTI3NTMyODUsImV4cCI6NDkwODQzMDQ4NSwiY2FwIjpbInRlc3QiLCJ0ZXN0LmNoaWxkMSIsInRlc3QuY2hpbGQyIiwidGVzdC5jaGlsZDMiXX0.FLqHSBq45d7tFkYMNZopKPoJ2VuxGVS5FCdr11RHznQ';

        $token = $this->tokenParser->parse($data);

        $this->assertSame('HS256', $token->header->alg);
        $this->assertSame('JWT', $token->header->typ);
        $this->assertSame(3, $token->payload->sub);
        $this->assertSame('Cecile D\'Amore V', $token->payload->name);
        $this->assertSame('gstokes@example.com', $token->payload->email);
        $this->assertSame('2025-07-17T11:54:45+00:00', $token->payload->iat->format('c'));
        $this->assertSame('2125-07-17T12:54:45+00:00', $token->payload->exp->format('c'));
        $this->assertSame(['test', 'test.child1', 'test.child2', 'test.child3'], $token->payload->cap);

        $this->assertTrue($this->tokenParser->validateHeader($token));
        $this->assertTrue($this->tokenParser->validateSignature($token));
        $this->assertTrue($this->tokenParser->validateExpiration($token));

        // This should NOT throw an exception
        $this->tokenParser->parseAndValidate($data);
    }

    #[Depends('test_decode')]
    public function test_decode_invalid_header(): void
    {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IlVOS05PV04ifQ.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJnc3Rva2VzQGV4YW1wbGUuY29tIiwiaW5zIjoxLCJpYXQiOjE3NTI3NTMyODUsImV4cCI6NDkwODQzMDQ4NSwiY2FwIjpbInRlc3QiLCJ0ZXN0LmNoaWxkMSIsInRlc3QuY2hpbGQyIiwidGVzdC5jaGlsZDMiXX0.ABTIYQkK66zWHD2gsyDsxz3I91krIASAVT6hVrlR0vg';

        $token = $this->tokenParser->parse($data);

        $this->assertFalse($this->tokenParser->validateHeader($token));

        $this->expectException(InvalidJWTException::class);
        $this->expectExceptionMessage('Invalid JWT header');
        $this->tokenParser->parseAndValidate($data);
    }

    #[Depends('test_decode')]
    public function test_decode_invalid_signature(): void
    {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IlVOS05PV04ifQ.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJnc3Rva2VzQGV4YW1wbGUuY29tIiwiaW5zIjoxLCJpYXQiOiIyMDI1LTA3LTE3VDExOjU0OjQ1KzAwOjAwIiwiZXhwIjoiMjAyNS0wNy0xN1QxMjo1NDo0NSswMDowMCIsImNhcCI6WyJ0ZXN0IiwidGVzdC5jaGlsZDEiLCJ0ZXN0LmNoaWxkMiIsInRlc3QuY2hpbGQzIl19.Pkhfu6vhwqbzILhq2T6g_FJtz7c2PUdjJd3bZ2OWCfA';

        $token = $this->tokenParser->parse($data);

        $this->assertFalse($this->tokenParser->validateSignature($token));

        $this->expectException(InvalidJWTException::class);
        $this->expectExceptionMessage('Invalid JWT signature');
        $this->tokenParser->parseAndValidate($data);
    }

    #[Depends('test_decode')]
    public function test_decode_invalid_expiration(): void
    {
        // Hardcoded expiration date in the past (2000-07-17T12:54:45+00:00)
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJnc3Rva2VzQGV4YW1wbGUuY29tIiwiaW5zIjoxLCJpYXQiOjk2MzgzNDg4NSwiZXhwIjo5NjM4MzQ4ODUsImNhcCI6WyJ0ZXN0IiwidGVzdC5jaGlsZDEiLCJ0ZXN0LmNoaWxkMiIsInRlc3QuY2hpbGQzIl19.2V_92fUeIfW1BptWc0pUDukINU419JQcm23Zio3SRwc';

        $token = $this->tokenParser->parse($data);

        $this->assertFalse($this->tokenParser->validateExpiration($token));

        $this->expectException(InvalidJWTException::class);
        $this->expectExceptionMessage('JWT token has expired');
        $this->tokenParser->parseAndValidate($data);
    }

    public function test_decode_empty_token(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('JWT secret must not be empty');

        new TokenParser('');
    }

    #[DataProvider('getInvalidDecodeData')]
    public function test_decode_invalid_decode(string $data): void
    {
        $this->expectException(InvalidJWTException::class);
        $this->expectExceptionMessage('Cannot decode');

        $this->tokenParser->parse($data);
    }

    #[DataProvider('getInvalidFormats')]
    public function test_decode_invalid_format(string $data): void
    {
        $this->expectException(InvalidJWTException::class);
        $this->expectExceptionMessage('Invalid JWT format');

        $this->tokenParser->parse($data);
    }

    public function test_encode(): void
    {
        $signature = Token::base64UrlDecode('y05BUhX6AZIKCxQhbLXdwlxv78LDK8h5oy9WCvpwrpk');
        $this->assertIsString($signature);
        $token = new Token(
            new Header(alg: 'HS256', typ: 'JWT'),
            new Payload(
                sub: 3,
                name: 'Cecile D\'Amore V',
                email: 'example@example.com',
                ins: 1,
                iat: new DateTimeImmutable('2025-07-17T11:54:45+00:00'),
                exp: new DateTimeImmutable('2125-07-17T12:54:45+00:00'),
                cap: ['client' => ['test', 'test.child1', 'test.child2', 'test.child3']]
            ),
            $signature // Example signature
        );

        $encoded = $token->encode();
        $this->assertSame(
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJleGFtcGxlQGV4YW1wbGUuY29tIiwiaW5zIjoxLCJpYXQiOjE3NTI3NTMyODUsImV4cCI6NDkwODQzMDQ4NSwiY2FwIjp7ImNsaWVudCI6WyJ0ZXN0IiwidGVzdC5jaGlsZDEiLCJ0ZXN0LmNoaWxkMiIsInRlc3QuY2hpbGQzIl19fQ.y05BUhX6AZIKCxQhbLXdwlxv78LDK8h5oy9WCvpwrpk',
            $encoded
        );

        $jsonEncoded = json_encode($token, JSON_THROW_ON_ERROR);
        $this->assertSame(
            '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjMsIm5hbWUiOiJDZWNpbGUgRCdBbW9yZSBWIiwiZW1haWwiOiJleGFtcGxlQGV4YW1wbGUuY29tIiwiaW5zIjoxLCJpYXQiOjE3NTI3NTMyODUsImV4cCI6NDkwODQzMDQ4NSwiY2FwIjp7ImNsaWVudCI6WyJ0ZXN0IiwidGVzdC5jaGlsZDEiLCJ0ZXN0LmNoaWxkMiIsInRlc3QuY2hpbGQzIl19fQ.y05BUhX6AZIKCxQhbLXdwlxv78LDK8h5oy9WCvpwrpk"',
            $jsonEncoded
        );
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->tokenParser = new TokenParser(self::SECRET);
    }
}
