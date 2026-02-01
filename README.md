# Laravel JWT library for OTT PM project.

Helper library for working with JWT tokens in Laravel applications within the OTT PM ecosystem.

## Installation

Add esoul repository to your composer.json if you haven't done so:

```json
{
  "repositories": [
    {
      "type": "composer",
      "url": "https://packages.esoul.cz/"
    }
  ]
}
```

Then install the package via composer:

```bash
composer require esoul/laravel-ott-jwt
```

## Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag="ott-jwt-config"   
```

This will create a configuration file at `config/jwt.php`.

Inside the configuration file, you should update the `capability_prefix` option and define all available capabilities that your module supports (without the prefix).

```php
return [
    'secret' => env('JWT_SECRET', bin2hex(random_bytes(32))),
    'token_validity' => env('JWT_VALIDITY', '+1 hour'),
    'capability_prefix' => 'todo-',
    'available_capabilities' => [
        // Define available capabilities here
        App\Policies\TaskPolicy::ADMIN_CAP => [
            'identifier' => App\Policies\TaskPolicy::ADMIN_CAP,
            'description' => 'Administrative capabilities for tasks',
        ],
        App\Policies\TaskPolicy::READ_CAP => [
            'identifier' => App\Policies\TaskPolicy::READ_CAP,
            'description' => 'Allows reading task data',
            'parent' => App\Policies\TaskPolicy::ADMIN_CAP,
        ],
        // Add more capabilities as needed
];
```

It's recommended to define capability identifiers as constants in your Policy classes for better maintainability.

```php
namespace App\Policies;

class TaskPolicy
{
    public const string ADMIN_CAP = 'task-admin';

    public const string READ_CAP = 'task-read';

    // Policy methods...
}
```

### Environment Variables

You can set the following environment variables in your `.env` file:

- `JWT_SECRET`: The secret key used for signing JWT tokens. If not set, a random key will be generated each time a configuration is loaded (for testing only).
- `JWT_VALIDITY`: The validity period of the JWT token (e.g., `+1 hour`, `+30 minutes` - in [PHP supported datetime formats](https://www.php.net/manual/en/datetime.formats.php)).

## Usage

Upon installation, the package will register the `JwtGuard` authentication guard as `jwt`. You can add it to your `config/auth.php` file:

```php
'guards' => [
    'api' => [
        'driver' => 'jwt',
        'provider' => null
    ]
]
```

And then use it in your routes or controllers:

```php
Route::middleware('auth:api')->group(function () {
    // Register your protected routes here
});
```

### Writing policies

`JwtGuard` automatically populates the authenticated user with a `JwtUser` instance, which provides methods for checking capabilities.

You can create policies that utilize these capabilities for authorization checks. Here's an example of a policy class:

```php
namespace App\Policies;

class TaskPolicy
{
    public const string ADMIN_CAP = 'task-admin';

    public const string READ_CAP = 'task-read';

    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(JwtUser $user, ?int $projectId = null): bool
    {
        return $user->can(self::READ_CAP, $projectId);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(JwtUser $user, Task $task): bool
    {
        return $user->can(self::READ_CAP, $task->projectId);
    }
    
    // Other policy methods...
}
```

### Authorization

JWT contain a list of capabilities assigned to the user in the `cap` claim.
This is not a simple list, but an object of capability lists per SaaS client or project ID.
Common SaaS-wide capabilities are stored under the `client` key.
Project-specific capabilities are stored under their respective project IDs.

You can check if a user has a specific capability using the `can` method of the `JwtUser` class:

> The `can` method accepts the capability identifier. It will automatically prepend the configured capability prefix if not already present.

```php
// Check only for SaaS-wide capability (the `client` key in the `cap` claim)
if ($user->can('task-create')) {
    // The user has the 'todo-create' capability for the current SaaS client
}

// Check for project-specific capability
$projectId = 123;
if ($user->can('task-create', $projectId)) {
    // The user has the 'todo-create' capability for project with ID 123
}
```

The SaaS-wide capabilities are overriding project-specific capabilities. 
For example, if a user has the `task-admin` capability for the SaaS client, it does not matter if they lack the same capability for a specific project; they will still have it for that project.

You can also check multiple capabilities at once using the `canAny` and `canAll` methods:

```php
$capabilities = ['task-create', 'task-edit'];
if ($user->canAny($capabilities, $projectId)) {
    // The user has at least one of the specified capabilities for project with ID 123
}

if ($user->canAll($capabilities, $projectId)) {
    // The user has all the specified capabilities for the project with ID 123
}
```

To get the raw JWT object form the user, you can access it via the readonly property on the `JwtUser` instance:

```php
$jwt = $user->token;
```

### JWT parser

The library exposes a `JwtParser` facade for parsing and validating JWT tokens.

You can use it as follows:

```php

use Esoul\OttJwt\Facades\JwtParser;
use Esoul\OttJwt\Jwt\Exceptions\InvalidJWTException;

$jwtString = '...'; // Your JWT string

// Parse and return the Esoul\OttJwt\Jwt\Token object.
// This does not validate the signature or expiration.
$jwt = JwtParser::parse($jwtString);

try {
    // Parse and validate the JWT (signature, expiration, etc.)
    $validatedJwt = JwtParser::parseAndValidate($jwtString);
} catch (InvalidJWTException $e) {
    // Handle invalid JWT (invalid signature, expired, etc.)
}

// Or validate the token separately
if (!JwtParser::validateSignature($token)) {
    // Invalid signature
}
if (!JwtParser::validateHeader($token)) {
    // Invalid header
}
if (!JwtParser::validateExpiration($token)) {
    // Token expired
}

// Transform the token back into a JWT string - all these methods are equivalent:
$serialized = json_encode($token);
$encoded = $token->encode();
$cast = (string)$token;
```