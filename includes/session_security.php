<?php
require_once __DIR__ . '/otp.php';

function auth_settings(): array {
    static $settings;
    return $settings ??= require __DIR__ . '/../config/security.php';
}

function auth_identifier_hash(string $identifier): string {
    return hash('sha256', strtolower(trim($identifier)));
}

function auth_account_hash(int $id): string {
    return hash('sha256', "account:$id");
}

function auth_client_ip_binary(): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        throw new RuntimeException('Invalid client address.');
    }
    return inet_pton($ip);
}

function auth_log_event(PDO $pdo, string $type, ?string $typed, ?int $id, string $details = ''): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $browser = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $stmt = $pdo->prepare('INSERT INTO security_events
        (event_type, username_typed, user_id, ip_address, user_agent, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())');
    $stmt->execute([$type, $typed === null ? null : mb_strcut(mb_scrub($typed, 'UTF-8'), 0, 65535, 'UTF-8'),
        $id, filter_var($ip, FILTER_VALIDATE_IP) ? inet_ntop(inet_pton($ip)) : null,
        mb_substr(mb_scrub($browser, 'UTF-8'), 0, 512, 'UTF-8'), $details]);
}

function auth_get_login_state(PDO $pdo, string $hash): array {
    $stmt = $pdo->prepare('SELECT failed_count, lockout_tier,
        GREATEST(0, TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), lockout_until)) AS locked_seconds
        FROM auth_login_state WHERE identifier_hash = ?');
    $stmt->execute([$hash]);
    return $stmt->fetch() ?: ['failed_count' => 0, 'lockout_tier' => 0, 'locked_seconds' => 0];
}

function auth_record_failed_login(PDO $pdo, string $hash): array {
    $settings = auth_settings();
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('INSERT IGNORE INTO auth_login_state (identifier_hash, updated_at) VALUES (?, UTC_TIMESTAMP())');
        $stmt->execute([$hash]);
        $stmt = $pdo->prepare('SELECT failed_count, lockout_tier, lockout_until FROM auth_login_state WHERE identifier_hash = ? FOR UPDATE');
        $stmt->execute([$hash]);
        $state = $stmt->fetch();
        $count = (int)$state['failed_count'];
        $tier = (int)$state['lockout_tier'];
        $until = $state['lockout_until'];
        $seconds = 0;
        $newTier = false;
        if (!$until || strtotime($until . ' UTC') <= time()) {
            $count++;
            if ($count >= $settings['lockout_attempts']) {
                $nextTier = min($tier + 1, count($settings['lockout_tiers_seconds']));
                $newTier = $nextTier > $tier;
                $tier = $nextTier;
                $seconds = $settings['lockout_tiers_seconds'][$tier - 1];
                $count = 0;
                $until = gmdate('Y-m-d H:i:s', time() + $seconds);
            }
            $stmt = $pdo->prepare('UPDATE auth_login_state SET failed_count = ?, lockout_tier = ?,
                lockout_until = ?, updated_at = UTC_TIMESTAMP() WHERE identifier_hash = ?');
            $stmt->execute([$count, $tier, $until, $hash]);
        }
        $pdo->commit();
        return ['failed_count' => $count, 'lockout_tier' => $tier, 'lockout_seconds' => $seconds, 'new_tier' => $newTier];
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $error;
    }
}

function auth_delete_login_states(PDO $pdo, array $hashes): void {
    if ($hashes) {
        $placeholders = implode(', ', array_fill(0, count($hashes), '?'));
        $stmt = $pdo->prepare("DELETE FROM auth_login_state WHERE identifier_hash IN ($placeholders)");
        $stmt->execute(array_values($hashes));
    }
}

function auth_ip_block_seconds(PDO $pdo, string $ip): int {
    $stmt = $pdo->prepare('SELECT GREATEST(0, TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), blocked_until))
        FROM auth_ip_blocks WHERE ip_address = ?');
    $stmt->execute([$ip]);
    return (int)$stmt->fetchColumn();
}

function auth_record_ip_failure(PDO $pdo, string $hash, string $ip, string $typed, ?int $id): void {
    $settings = auth_settings();
    $cutoff = gmdate('Y-m-d H:i:s', time() - $settings['ip_block_window_seconds']);
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('INSERT IGNORE INTO auth_ip_blocks (ip_address, blocked_until) VALUES (?, UTC_TIMESTAMP())');
        $stmt->execute([$ip]);
        $stmt = $pdo->prepare('SELECT blocked_until > UTC_TIMESTAMP() FROM auth_ip_blocks WHERE ip_address = ? FOR UPDATE');
        $stmt->execute([$ip]);
        if ($stmt->fetchColumn()) {
            $pdo->commit();
            return;
        }
        $stmt = $pdo->prepare('INSERT INTO auth_login_attempts (identifier_hash, ip_address, attempt_at) VALUES (?, ?, UTC_TIMESTAMP())');
        $stmt->execute([$hash, $ip]);
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM auth_login_attempts WHERE ip_address = ? AND attempt_at > ?');
        $stmt->execute([$ip, $cutoff]);
        $count = (int)$stmt->fetchColumn();
        $blocked = $count >= $settings['ip_block_threshold'];
        if ($blocked) {
            $expires = time() + $settings['ip_block_duration_seconds'];
            $stmt = $pdo->prepare('UPDATE auth_ip_blocks SET blocked_until = ? WHERE ip_address = ?');
            $stmt->execute([gmdate('Y-m-d H:i:s', $expires), $ip]);
            auth_log_event($pdo, 'IP_BLOCKED', $typed, $id, 'threshold=' . $settings['ip_block_threshold']);
        }
        $pdo->commit();
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $error;
    }
    if ($blocked) {
        $expiry = (new DateTimeImmutable('@' . $expires))->setTimezone(new DateTimeZone('Asia/Manila'))->format('M j, Y g:i:s A');
        $stmt = $pdo->prepare("SELECT DISTINCT u.id, u.email FROM auth_login_attempts a JOIN users u
            ON a.identifier_hash = SHA2(CONCAT('account:', u.id), 256)
            WHERE a.ip_address = ? AND a.attempt_at > ? AND u.email_verified = 1");
        $stmt->execute([$ip, $cutoff]);
        foreach ($stmt->fetchAll() as $owner) {
            auth_send_security_alert($pdo, 'Water Go security alert: sign-in IP blocked',
                "Water Go detected failed sign-in attempts from an IP address used to access your account. As a security precaution, access from that address has been temporarily blocked.\n\n"
                . "Failed attempts from this IP: $count\nBlock expires: $expiry Philippine time",
                null, (int)$owner['id'], $owner['email']);
        }
    }
}

function auth_record_failure(PDO $pdo, string $hash, string $typed, ?array $account, string $purpose): void {
    $attempt = auth_record_failed_login($pdo, $hash);
    $id = $account ? (int)$account['id'] : null;
    auth_record_ip_failure($pdo, $hash, auth_client_ip_binary(), $typed, $id);
    if ($attempt['lockout_seconds'] > 0) {
        auth_log_event($pdo, 'LOCKOUT_TIER_' . $attempt['lockout_tier'], $typed, $id,
            'purpose=' . $purpose . '; duration_seconds=' . $attempt['lockout_seconds']);
        if ($account && $attempt['new_tier']) {
            $count = $attempt['lockout_tier'] * auth_settings()['lockout_attempts'];
            auth_send_security_alert($pdo, 'Failed sign-in attempts on your account',
                "A temporary lockout was triggered after $count failed attempts.", $typed, $id, $account['email']);
        }
    }
}

function auth_send_security_alert(PDO $pdo, string $subject, string $message, ?string $typed, ?int $id, string $recipient): bool {
    $time = (new DateTimeImmutable('now', new DateTimeZone('Asia/Manila')))->format('Y-m-d H:i:s T');
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $ip = inet_ntop(inet_pton($ip));
        if ($ip === '::1' || $ip === '127.0.0.1') {
            $ip = '127.0.0.1 (Localhost)';
        }
    } else {
        $ip = 'Unavailable';
    }
    $browser = mb_substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 512);
    $url = rtrim($GLOBALS['waterGoPrivate']['base_url'] ?? 'http://localhost/water_go', '/') . '/forgot_password.php';
    $sent = auth_send_mail($recipient, $subject, "$message\n\nEvent time: $time\nSource IP address: $ip\nBrowser: $browser\n\nIf you did not initiate these attempts or changes, reset your password: $url");
    if ($sent) {
        auth_log_event($pdo, 'ALERT_EMAIL_SENT', $typed, $id, 'alert=' . $subject);
    }
    return $sent;
}

function auth_find_account(PDO $pdo, string $identifier): ?array {
    $stmt = $pdo->prepare('SELECT u.id, u.full_name, u.email, u.password, u.role,
        COALESCE(u.admin_username, p.username) AS username, (u.admin_totp_secret IS NOT NULL) AS has_authenticator
        FROM users u LEFT JOIN staff_registration_profiles p ON p.user_id = u.id
        WHERE u.email_verified = 1 AND (u.email = ? OR u.admin_username = ? OR p.username = ?) LIMIT 1');
    $stmt->execute([$identifier, $identifier, $identifier]);
    return $stmt->fetch() ?: null;
}

function auth_valid_username(string $username): bool {
    $settings = auth_settings();
    return strlen($username) >= $settings['username_min_length'] && strlen($username) <= $settings['username_max_length']
        && preg_match('/^[A-Za-z][A-Za-z0-9]*$/D', $username);
}

function auth_dummy_hash(): string {
    return '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.';
}

function auth_csrf_token(string $key): string {
    return $_SESSION[$key] ??= bin2hex(random_bytes(32));
}

function auth_valid_csrf(string $key, string $token): bool {
    return isset($_SESSION[$key]) && is_string($_SESSION[$key]) && hash_equals($_SESSION[$key], $token);
}

function auth_login_url(): string {
    $directory = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
    return rtrim(preg_replace('~/(admin|staff)$~', '', $directory), '/') . '/login.php';
}

function auth_dashboard_path(string $role): ?string {
    return match ($role) {
        'admin' => 'admin/dashboard.php',
        'staff' => 'staff/dashboard.php',
        default => null,
    };
}

function auth_current_user(PDO $pdo, bool $refreshActivity = true): ?array {
    $user = $_SESSION['user'] ?? null;
    if (!is_array($user) || ($_SESSION['login_otp_verified'] ?? false) !== true) {
        return null;
    }
    $now = time();
    if ($now - (int)($_SESSION['last_activity'] ?? 0) >= auth_settings()['idle_session_timeout_seconds']) {
        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['auth_notice'] = 'Your session expired due to inactivity. Please sign in again.';
        return null;
    }

    $stmt = $pdo->prepare('SELECT role FROM users WHERE id = ? AND email_verified = 1');
    $stmt->execute([(int)$user['id']]);
    $role = $stmt->fetchColumn();
    if (!is_string($role) || auth_dashboard_path($role) === null) {
        $_SESSION = [];
        session_regenerate_id(true);
        return null;
    }

    $user['role'] = $role;
    $_SESSION['user'] = $user;
    if ($refreshActivity) {
        $_SESSION['last_activity'] = $now;
    }
    return $user;
}

function require_login(): void {
    if (empty($_SESSION['user']) || ($_SESSION['login_otp_verified'] ?? false) !== true) {
        header('Location: ' . auth_login_url());
        exit;
    }
    $pdo = $GLOBALS['pdo'] ?? null;
    if (!$pdo instanceof PDO) {
        require __DIR__ . '/../config/database.php';
        $GLOBALS['pdo'] = $pdo;
    }
    if (auth_current_user($pdo) === null) {
        header('Location: ' . auth_login_url());
        exit;
    }
}

function require_role(string $role): void {
    require_login();
    if ($_SESSION['user']['role'] !== $role) {
        http_response_code(403);
        exit('Access denied.');
    }
}

function auth_logout_form(string $url, string $label): void {
    ?>
    <form method="post" action="<?= htmlspecialchars($url) ?>" class="logout-form">
      <input type="hidden" name="csrf_token" value="<?= auth_csrf_token('logout_csrf') ?>">
      <button type="submit"><?= htmlspecialchars($label) ?></button>
    </form>
    <?php
}

// Call inside a transaction after locking the matching users row.
function auth_save_new_password(PDO $pdo, int $userId, string $currentHash, string $password): bool {
    $stmt = $pdo->prepare('SELECT id, password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT 2');
    $stmt->execute([$userId]);
    $history = $stmt->fetchAll();
    foreach (array_merge([$currentHash], array_column($history, 'password_hash')) as $hash) {
        if (password_verify($password, $hash)) {
            return false;
        }
    }

    $stmt = $pdo->prepare('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)');
    $stmt->execute([$userId, $currentHash]);
    if ($history) {
        $stmt = $pdo->prepare('DELETE FROM password_history WHERE user_id = ? AND id < ?');
        $stmt->execute([$userId, $history[0]['id']]);
    }
    $stmt = $pdo->prepare('UPDATE users SET password = ? WHERE id = ?');
    $stmt->execute([password_hash($password, PASSWORD_ARGON2ID), $userId]);
    $stmt = $pdo->prepare('UPDATE auth_login_otps SET used_at = UTC_TIMESTAMP() WHERE user_id = ? AND used_at IS NULL');
    $stmt->execute([$userId]);
    $stmt = $pdo->prepare('UPDATE password_reset_otps SET used_at = UTC_TIMESTAMP() WHERE user_id = ? AND used_at IS NULL');
    $stmt->execute([$userId]);
    return true;
}

function auth_run_monitor(PDO $pdo): void {
    $manila = new DateTimeZone('Asia/Manila');
    $now = new DateTimeImmutable('now', $manila);
    $stmt = $pdo->prepare('SELECT event_type, user_id, username_typed, ip_address, created_at
        FROM security_events WHERE created_at >= ? AND created_at <= UTC_TIMESTAMP() ORDER BY created_at, id');
    $stmt->execute([gmdate('Y-m-d H:i:s', $now->getTimestamp() - 86400)]);
    $scanned = 0;
    $ipFailures = $accountIps = $otpFailures = $offHours = [];
    while ($event = $stmt->fetch()) {
        $scanned++;
        $name = mb_strtolower(trim($event['username_typed'] ?? ''), 'UTF-8');
        $ip = $event['ip_address'];
        $id = $event['user_id'];
        $at = strtotime($event['created_at'] . ' UTC');
        if ($event['event_type'] === 'LOGIN_FAILED' && $ip !== null) {
            $ipFailures[$ip] = ($ipFailures[$ip] ?? 0) + 1;
            if ($name !== '') {
                $accountIps[$name][$ip] = true;
            }
        } elseif ($event['event_type'] === 'OTP_FAILED' && $id !== null) {
            $otpFailures[$id]['name'] = $name ?: "Account $id";
            $otpFailures[$id]['times'][] = $at;
        } elseif ($event['event_type'] === 'LOGIN_SUCCESS' && $id !== null) {
            $local = (new DateTimeImmutable('@' . $at))->setTimezone($manila);
            if ((int)$local->format('G') < 5) {
                $offHours[$id] = [$name ?: "Account $id", 'Sign-in at ' . $local->format('Y-m-d H:i P')];
            }
        }
    }
    $flags = [];
    foreach ($ipFailures as $ip => $count) {
        if ($count >= auth_settings()['ip_block_threshold']) {
            $flags[] = ['IP_OVER_THRESHOLD', 'High', $ip, $ip, "$count failures in the last 24 hours"];
        }
    }
    foreach ($accountIps as $name => $ips) {
        if (count($ips) >= 3) {
            $flags[] = ['ACCOUNT_TARGETED', 'Medium', hash('sha256', (string)$name), (string)$name, count($ips) . ' distinct source IPs'];
        }
    }
    foreach ($otpFailures as $id => $failures) {
        $times = $failures['times'];
        for ($i = 4; $i < count($times); $i++) {
            if ($times[$i] - $times[$i - 4] <= 600) {
                $flags[] = ['OTP_GUESSING', 'Medium', (string)$id, $failures['name'], 'At least five OTP failures in 10 minutes'];
                break;
            }
        }
    }
    foreach ($offHours as $id => [$name, $description]) {
        $flags[] = ['OFF_HOURS_LOGIN', 'Low', (string)$id, $name, $description];
    }
    $insert = $pdo->prepare('INSERT IGNORE INTO security_flags
        (flag_type, severity, target_key, affected_target, description, detected_at, detected_day)
        VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP(), ?)');
    $new = 0;
    printf("IT 107 Monitoring Report - %s PHT\nScanned: %d events (last 24 hours)\n", $now->format('Y-m-d H:i'), $scanned);
    foreach ($flags as [$type, $severity, $key, $target, $description]) {
        $target = mb_substr(preg_replace('/[\p{C}]/u', '', $target), 0, 255, 'UTF-8');
        $insert->execute([$type, $severity, $key, $target, $description, $now->format('Y-m-d')]);
        $new += $insert->rowCount();
        printf("[%s] %s %s - %s\n", strtoupper($severity), $type, $target, $description);
    }
    printf("New flags written: %d. Already flagged today: %d.\n", $new, count($flags) - $new);
}
