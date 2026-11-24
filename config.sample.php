<?php
return [
    'base_url' => 'http://localhost/water_go',
    'database' => ['host' => 'localhost', 'name' => 'water_go', 'user' => 'water_go_app', 'password' => 'replace-me'],
    'smtp' => ['host' => 'smtp.example.com', 'port' => 587, 'username' => 'sender@example.com',
               'password' => 'replace-me', 'encryption' => 'tls', 'from' => 'sender@example.com'],
    'recaptcha' => ['site_key' => 'replace-me', 'secret_key' => 'replace-me'],
    'encryption_key' => 'replace-with-base64-encoded-32-random-bytes',
    'error_log' => 'C:/xampp/water_go_errors.log',
];
