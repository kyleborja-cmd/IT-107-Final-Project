<?php
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit('Page Not Found');
}
require __DIR__ . '/../config/database.php';
require __DIR__ . '/../includes/profile_validation.php';
require_once __DIR__ . '/../includes/session_security.php';

$name = trim(getenv('WATER_GO_ADMIN_NAME') ?: '');
$email = mb_strtolower(trim(getenv('WATER_GO_ADMIN_EMAIL') ?: ''));
$username = trim(getenv('WATER_GO_ADMIN_USERNAME') ?: '');
$password = getenv('WATER_GO_ADMIN_PASSWORD') ?: '';
if ($name === '' || registration_length($name) > 500 || strlen($email) > 100
    || !filter_var($email, FILTER_VALIDATE_EMAIL) || !auth_valid_username($username) || registration_length($password) > 64
    || registration_password_strength($password) !== 'Strong') {
    fwrite(STDERR, "Set a name, a 6-to-20-character username, a valid mailbox and a Strong password between 12 and 64 characters.\n");
    exit(1);
}
$stmt = $pdo->prepare('SELECT 1 FROM staff_registration_profiles WHERE username = ?');
$stmt->execute([$username]);
if ($stmt->fetchColumn()) {
    fwrite(STDERR, "That username is already registered.\n");
    exit(1);
}
$stmt = $pdo->prepare('INSERT INTO users (full_name, email, password, role, email_verified, admin_username) VALUES (?, ?, ?, ?, 1, ?)');
try {
    $stmt->execute([$name, $email, password_hash($password, PASSWORD_ARGON2ID), 'admin', $username]);
    echo "Administrator created. Sign in with the username and complete the email OTP.\n";
} catch (PDOException $e) {
    error_log($e->getMessage());
    fwrite(STDERR, "Could not create the administrator. Check whether the username or email is already registered.\n");
    exit(1);
}
