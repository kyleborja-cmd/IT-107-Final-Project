<?php
require_once __DIR__ . '/../includes/bootstrap.php';
$database = $GLOBALS['waterGoPrivate']['database'] ?? [];
$host = ($database['host'] ?? getenv('WATER_GO_DB_HOST'));
$db = ($database['name'] ?? getenv('WATER_GO_DB_NAME'));
$user = ($database['user'] ?? getenv('WATER_GO_DB_USER'));
$pass = ($database['password'] ?? getenv('WATER_GO_DB_PASSWORD'));
$host = is_string($host) && $host !== '' ? $host : 'localhost';
$db = is_string($db) && $db !== '' ? $db : 'water_go';
$user = is_string($user) && $user !== '' ? $user : 'root';
$pass = is_string($pass) ? $pass : '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    http_response_code(500);
    error_log($e->getMessage());
    exit('The service is temporarily unavailable.');
}
