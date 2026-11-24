<?php
require __DIR__ . '/includes/session_security.php';

$method = $_SERVER['REQUEST_METHOD'] ?? '';
if (!in_array($method, ['GET', 'POST'], true)) {
    header('Allow: GET, POST');
    http_response_code(405);
    exit;
}
if (empty($_SESSION['user']) || ($_SESSION['login_otp_verified'] ?? false) !== true) {
    http_response_code(401);
    exit;
}
$refresh = $method === 'POST';
if ($refresh && !auth_valid_csrf('dashboard_activity_csrf', $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) {
    http_response_code(403);
    exit;
}

require __DIR__ . '/config/database.php';
if (auth_current_user($pdo, $refresh) === null) {
    http_response_code(401);
    exit;
}
header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'remaining' => max(0, auth_settings()['idle_session_timeout_seconds'] - (time() - (int)$_SESSION['last_activity'])),
]);
