<?php

declare(strict_types=1);

return [
    'secret' => env('JWT_SECRET', bin2hex(random_bytes(32))),
    'token_validity' => env('JWT_VALIDITY', '+1 hour'),
];
