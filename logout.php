<?php
require_once __DIR__ . '/includes/session_security.php';
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit;
}
if (!auth_valid_csrf('logout_csrf', is_string($_POST['csrf_token'] ?? null) ? $_POST['csrf_token'] : '')) {
    if (!empty($_SESSION['user'])) {
        require __DIR__ . '/config/database.php';
        auth_log_event($pdo, 'CSRF_REJECTED', null, (int)$_SESSION['user']['id'], 'purpose=logout');
    }
    http_response_code(403);
    exit('Reload your page and try again.');
}
$_SESSION = [];
$params = session_get_cookie_params();
setcookie(session_name(), '', [
    'expires' => time() - 3600,
    'path' => $params['path'],
    'domain' => $params['domain'],
    'secure' => $params['secure'],
    'httponly' => $params['httponly'],
    'samesite' => $params['samesite'],
]);
session_destroy();
$destination = ($_POST['destination'] ?? '') === 'home' ? 'index.php' : 'login.php';
header('Location: ' . $destination, true, 303);
exit;
