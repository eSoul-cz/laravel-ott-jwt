<?php

declare(strict_types=1);

return [
    'secret' => env('JWT_SECRET', bin2hex(random_bytes(32))),
    'token_validity' => env('JWT_VALIDITY', '+1 hour'),
    'capability_prefix' => '',
    'available_capabilities' => [
        // Define available capabilities here
        // 'admin-model' => [
        //    'identifier' => 'admin-model',
        //    'description' => 'Allows admin operations on model data',
        // ],
        // 'read-model' => [
        //    'identifier' => 'read-model',
        //    'description' => 'Allows reading model data',
        //    'parent' => 'admin-model',
        // ]
    ],
];
