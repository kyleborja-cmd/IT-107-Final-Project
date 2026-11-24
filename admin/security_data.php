<?php
ini_set('display_errors', '0');
error_reporting(E_ALL);
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, private');
header('Content-Type: application/json; charset=utf-8');

require '../includes/session_security.php';
require '../config/database.php';

function security_json_error(int $status, string $message): void {
    http_response_code($status);
    if ($status === 401 || empty($_SESSION['user'])) { exit; }
    echo json_encode(['error' => $message], JSON_UNESCAPED_SLASHES);
    exit;
}

$user = auth_current_user($pdo, false);
if (($user['role'] ?? null) !== 'admin') {
    auth_log_event(
        $pdo,
        'ADMIN_ACCESS_DENIED',
        $user ? (string)($user['username'] ?? $user['email'] ?? '') : null,
        $user ? (int)$user['id'] : null,
        'endpoint=security_data'
    );
    security_json_error(403, 'Access denied');
}

$manila = new DateTimeZone('Asia/Manila');
$utc = new DateTimeZone('UTC');
$nowManila = new DateTimeImmutable('now', $manila);
$todayStart = $nowManila->setTime(0, 0)->setTimezone($utc)->format('Y-m-d H:i:s');
$tomorrowStart = $nowManila->setTime(0, 0)->modify('+1 day')->setTimezone($utc)->format('Y-m-d H:i:s');
$nowUtc = new DateTimeImmutable('now', $utc);
$hourStart = $nowUtc->setTime((int)$nowUtc->format('H'), 0);
$chartStart = $hourStart->modify('-23 hours');
$chartEnd = $hourStart->modify('+1 hour');

$stmt = $pdo->prepare(
    "SELECT event_type, COUNT(*) AS total
     FROM security_events
     WHERE created_at >= ? AND created_at < ?
       AND event_type IN ('LOGIN_SUCCESS','LOGIN_FAILED','OTP_SENT','OTP_FAILED','ALERT_EMAIL_SENT')
     GROUP BY event_type"
);
$stmt->execute([$todayStart, $tomorrowStart]);
$totals = array_fill_keys(['LOGIN_SUCCESS', 'LOGIN_FAILED', 'OTP_SENT', 'OTP_FAILED', 'ALERT_EMAIL_SENT'], 0);
foreach ($stmt->fetchAll() as $row) {
    $totals[$row['event_type']] = (int)$row['total'];
}

$stmt = $pdo->prepare(
    "SELECT COUNT(*)
     FROM auth_login_state s
     INNER JOIN users u ON s.identifier_hash = SHA2(CONCAT('account:', u.id), 256)
     WHERE s.lockout_until > UTC_TIMESTAMP()"
);
$stmt->execute();
$lockedAccounts = (int)$stmt->fetchColumn();
$stmt = $pdo->prepare('SELECT COUNT(*) FROM auth_ip_blocks WHERE blocked_until > UTC_TIMESTAMP()');
$stmt->execute();
$blockedIps = (int)$stmt->fetchColumn();

$labels = [];
$chartHours = [];
$chartCounts = [];
$chartStartString = $chartStart->format('Y-m-d H:i:s');
$chartEndString = $chartEnd->format('Y-m-d H:i:s');
$stmt = $pdo->prepare(
    "SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00:00') AS hour_bucket, COUNT(*) AS total
     FROM security_events
     WHERE event_type = 'LOGIN_FAILED' AND created_at >= ? AND created_at < ?
     GROUP BY hour_bucket"
);
$stmt->execute([$chartStartString, $chartEndString]);
$countsByHour = [];
foreach ($stmt->fetchAll() as $row) {
    $countsByHour[$row['hour_bucket']] = (int)$row['total'];
}
for ($i = 0; $i < 24; $i++) {
    $bucket = $chartStart->modify('+' . $i . ' hours');
    $localHour = $bucket->setTimezone($manila);
    $labels[] = $localHour->format('M j H:i');
    $chartHours[] = [
        'key' => $bucket->format(DateTimeInterface::ATOM),
        'start' => $localHour->format('M j, Y g:i A'),
        'end' => $localHour->modify('+1 hour')->format('M j, Y g:i A'),
        'tick' => $localHour->format('H:i'),
        'in_progress' => $i === 23,
    ];
    $chartCounts[] = $countsByHour[$bucket->format('Y-m-d H:00:00')] ?? 0;
}

$last24Hours = gmdate('Y-m-d H:i:s', time() - 86400);
$stmt = $pdo->prepare(
    'SELECT INET6_NTOA(b.ip_address) AS ip_address, b.blocked_until,
            b.blocked_until > UTC_TIMESTAMP() AS active, e.username_typed, e.created_at
     FROM auth_ip_blocks b
     LEFT JOIN security_events e ON e.id = (
         SELECT MAX(recent.id) FROM security_events recent
         WHERE recent.event_type = ? AND recent.ip_address = INET6_NTOA(b.ip_address)
           AND recent.created_at >= ?
     )
     WHERE b.blocked_until > ? AND (b.blocked_until > UTC_TIMESTAMP() OR e.id IS NOT NULL)
     ORDER BY active DESC, b.blocked_until DESC, b.ip_address'
);
$stmt->execute(['IP_BLOCKED', $last24Hours, $last24Hours]);
$ipBlocks = [];
foreach ($stmt as $block) {
    $ipBlocks[] = [
        'ip_address' => $block['ip_address'],
        'active' => (bool)$block['active'],
        'username' => $block['username_typed'],
        'blocked_at' => $block['created_at'] === null ? null :
            (new DateTimeImmutable($block['created_at'], $utc))->setTimezone($manila)->format('Y-m-d H:i:s T'),
        'expires_at' => (new DateTimeImmutable($block['blocked_until'], $utc))->setTimezone($manila)->format('Y-m-d H:i:s T'),
    ];
}

$stmt = $pdo->prepare(
    "SELECT ip_address, COUNT(*) AS failures
     FROM security_events
     WHERE event_type = 'LOGIN_FAILED' AND created_at >= ? AND ip_address IS NOT NULL
     GROUP BY ip_address
     ORDER BY failures DESC, ip_address ASC
     LIMIT ?"
);
$stmt->bindValue(1, $last24Hours);
$stmt->bindValue(2, 5, PDO::PARAM_INT);
$stmt->execute();
$ipRows = $stmt->fetchAll();
$topIps = [];
$stmt = $pdo->prepare('SELECT blocked_until FROM auth_ip_blocks WHERE ip_address = ? AND blocked_until > UTC_TIMESTAMP()');
foreach ($ipRows as $row) {
    $ip = (string)$row['ip_address'];
    $stmt->execute([inet_pton($ip)]);
    $expiresAt = $stmt->fetchColumn();
    $isBlocked = $expiresAt !== false;
    $topIps[] = [
        'ip_address' => $ip,
        'failures' => (int)$row['failures'],
        'blocked' => $isBlocked,
        'expires_at' => $expiresAt ? (new DateTimeImmutable($expiresAt, $utc))->setTimezone($manila)->format('Y-m-d H:i:s T') : null,
    ];
}

$stmt = $pdo->prepare(
    'SELECT flag_type, severity, affected_target, description, detected_at
     FROM security_flags ORDER BY detected_at DESC, id DESC LIMIT ?'
);
$stmt->bindValue(1, 50, PDO::PARAM_INT);
$stmt->execute();
$flags = $stmt->fetchAll();
foreach ($flags as &$flag) {
    $flag['detected_at'] = (new DateTimeImmutable($flag['detected_at'], $utc))->setTimezone($manila)->format('Y-m-d H:i:s T');
}
unset($flag);

$filters = [];
$params = [];
$dateFrom = is_string($_GET['date_from'] ?? null) ? trim($_GET['date_from']) : '';
$dateTo = is_string($_GET['date_to'] ?? null) ? trim($_GET['date_to']) : '';
$datePattern = '/^\d{4}-\d{2}-\d{2}$/D';
if (($dateFrom !== '' && !preg_match($datePattern, $dateFrom)) ||
    ($dateTo !== '' && !preg_match($datePattern, $dateTo))) {
    security_json_error(400, 'Invalid date filter');
}
$dateFromObj = $dateFrom !== '' ? DateTimeImmutable::createFromFormat('!Y-m-d', $dateFrom, $manila) : null;
$dateToObj = $dateTo !== '' ? DateTimeImmutable::createFromFormat('!Y-m-d', $dateTo, $manila) : null;
if (($dateFrom !== '' && (!$dateFromObj || $dateFromObj->format('Y-m-d') !== $dateFrom)) ||
    ($dateTo !== '' && (!$dateToObj || $dateToObj->format('Y-m-d') !== $dateTo))) {
    security_json_error(400, 'Invalid date filter');
}
if ($dateFromObj && $dateToObj) {
    if ($dateFromObj > $dateToObj || $dateFromObj->diff($dateToObj)->days > 366) {
        security_json_error(400, 'Date range must be ordered and no longer than 367 days');
    }
}
if ($dateFromObj) {
    $filters[] = 'created_at >= ?';
    $params[] = $dateFromObj->setTimezone($utc)->format('Y-m-d H:i:s');
}
if ($dateToObj) {
    $filters[] = 'created_at < ?';
    $params[] = $dateToObj->modify('+1 day')->setTimezone($utc)->format('Y-m-d H:i:s');
}
$eventType = is_string($_GET['event_type'] ?? null) ? trim($_GET['event_type']) : '';
$groups = require __DIR__ . '/../includes/security_statuses.php';
$statusByEvent = [];
foreach ($groups as $status => $eventTypes) {
    $statusByEvent += array_fill_keys($eventTypes, $status);
}
$statusFilter = is_string($_GET['status'] ?? null) ? trim($_GET['status']) : '';
if ($statusFilter !== '') {
    if (!isset($groups[$statusFilter])) {
        security_json_error(400, 'Invalid status filter');
    }
    $group = $groups[$statusFilter];
    $filters[] = 'event_type IN (' . implode(', ', array_fill(0, count($group), '?')) . ')';
    $params = array_merge($params, $group);
}
if ($eventType !== '' && !isset($statusByEvent[$eventType])) {
    security_json_error(400, 'Invalid event type filter');
}
if ($eventType !== '') {
    $filters[] = 'event_type = ?';
    $params[] = $eventType;
}
$usernameFilter = is_string($_GET['username'] ?? null) ? trim($_GET['username']) : '';
if (mb_strlen($usernameFilter, 'UTF-8') > 200) {
    security_json_error(400, 'Username filter is too long');
}
if ($usernameFilter !== '') {
    $filters[] = 'username_typed LIKE ?';
    $params[] = '%' . $usernameFilter . '%';
}
$ipFilter = is_string($_GET['ip_address'] ?? null) ? trim($_GET['ip_address']) : '';
if ($ipFilter !== '' && filter_var($ipFilter, FILTER_VALIDATE_IP) === false) {
    security_json_error(400, 'Invalid IP address filter');
}
if ($ipFilter === '127.0.0.1') {
    $filters[] = 'ip_address IN (?, ?)';
    $params[] = '127.0.0.1';
    $params[] = '::1';
} elseif ($ipFilter !== '') {
    $filters[] = 'ip_address = ?';
    $params[] = $ipFilter;
}
$where = $filters ? 'WHERE ' . implode(' AND ', $filters) : '';
$stmt = $pdo->prepare(
    'SELECT id, created_at, event_type, username_typed, user_id, ip_address, user_agent
     FROM security_events ' . $where . ' ORDER BY created_at DESC, id DESC LIMIT 50'
);
$stmt->execute($params);
$events = $stmt->fetchAll();
foreach ($events as &$event) {
    $event['status'] = $statusByEvent[$event['event_type']] ?? 'Recorded';
    $event['created_at'] = (new DateTimeImmutable($event['created_at'], $utc))->setTimezone($manila)->format('Y-m-d H:i:s T');
}
unset($event);

echo json_encode([
    'summary' => [
        'successful_logins' => $totals['LOGIN_SUCCESS'],
        'failed_logins' => $totals['LOGIN_FAILED'],
        'locked_accounts' => $lockedAccounts,
        'blocked_ips' => $blockedIps,
        'otps_sent' => $totals['OTP_SENT'],
        'failed_otp_attempts' => $totals['OTP_FAILED'],
        'alert_emails_sent' => $totals['ALERT_EMAIL_SENT'],
    ],
    'chart' => ['labels' => $labels, 'values' => $chartCounts, 'hours' => $chartHours],
    'top_ips' => $topIps,
    'ip_blocks' => $ipBlocks,
    'flags' => $flags,
    'events' => $events,
    'last_refresh' => (new DateTimeImmutable('now', $manila))->format('Y-m-d H:i:s T'),
], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
