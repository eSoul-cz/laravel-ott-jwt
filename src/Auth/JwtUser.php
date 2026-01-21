<?php
declare(strict_types=1);
namespace Esoul\OttJwt\Auth;

use Esoul\OttJwt\Jwt\Token;
use Illuminate\Contracts\Auth\Authenticatable;

readonly class JwtUser implements Authenticatable {

    public function __construct(
        public Token $token,
    ) {
    }

    private function normalizeCapability(string $capability): string
    {
        $prefix = config('jwt.capability_prefix');
        if ($prefix && !str_starts_with($capability, $prefix)) {
            return $prefix.$capability;
        }
        return $capability;
    }

    /**
     * @param non-empty-string $capability
     * @param int|null $projectId
     * @return bool
     */
    public function can(string $capability, ?int $projectId = null): bool
    {
        $capability = $this->normalizeCapability($capability);

        // Check main capabilities
        if (isset($token->payload->cap['client']) && in_array($capability, $this->token->payload->cap['client'], true)) {
            return true;
        }

        // Check project-specific capabilities
        if ($projectId !== null && isset($this->token->payload->cap[(string) $projectId])) {
            return in_array($capability, $this->token->payload->cap[(string) $projectId], true);
        }

        return false;
    }

    /**
     * @param non-empty-string[] $capabilities
     * @param int|null $projectId
     * @return bool
     */
    public function canAll(array $capabilities, ?int $projectId = null): bool
    {
        return array_all($capabilities, fn($capability) => $this->can($capability, $projectId));
    }

    /**
     * @param non-empty-string[] $capabilities
     * @param int|null $projectId
     * @return bool
     */
    public function canAny(array $capabilities, ?int $projectId = null): bool
    {
        return array_any($capabilities, fn($capability) => $this->can($capability, $projectId));
    }

    public function getAuthIdentifierName(): string
    {
        return 'sub';
    }

    /**
     * Gets capabilities from the token payload.
     */
    public function getAuthIdentifier(): int
    {
        return $this->token->payload->sub;
    }

    /**
     * @return string Empty, not used.
     */
    public function getAuthPassword(): string
    {
        return '';
    }

    /**
     * @return string Empty, not used.
     */
    public function getAuthPasswordName(): string
    {
        return '';
    }

    public function getRememberToken(): string
    {
        return '';
    }

    public function setRememberToken(mixed $value): void
    {
        // Not needed
    }

    public function getRememberTokenName(): string
    {
        return '';
    }
}