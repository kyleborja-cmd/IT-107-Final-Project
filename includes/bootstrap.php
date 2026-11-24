<?php
date_default_timezone_set('Asia/Manila');
$privatePath = getenv('WATER_GO_CONFIG_FILE') ?: dirname(__DIR__, 3) . '/water_go_config.php';
$GLOBALS['waterGoPrivate'] = is_file($privatePath) ? require $privatePath : [];
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', $GLOBALS['waterGoPrivate']['error_log'] ?? dirname(__DIR__, 3) . '/water_go_errors.log');
if (PHP_SAPI !== 'cli') {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, private');
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.use_strict_mode', '1');
        session_set_cookie_params([
            'httponly' => true,
            'samesite' => 'Lax',
            'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        ]);
        session_start();
    }
}
