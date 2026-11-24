<?php
require_once __DIR__ . '/bootstrap.php';

function auth_send_mail(string $to, string $subject, string $body): bool {
    $config = $GLOBALS['waterGoPrivate']['smtp'] ?? [];
    $autoload = __DIR__ . '/../vendor/autoload.php';
    if (!is_file($autoload) || empty($config['host'])) {
        error_log('Water Go SMTP is not configured.');
        return false;
    }
    require_once $autoload;
    try {
        $mailer = new PHPMailer\PHPMailer\PHPMailer(true);
        $mailer->isSMTP();
        $mailer->Timeout = 10;
        $mailer->Host = $config['host'];
        $mailer->Port = (int)($config['port'] ?? 587);
        $mailer->SMTPAuth = !empty($config['username']);
        $mailer->Username = $config['username'] ?? '';
        $mailer->Password = $config['password'] ?? '';
        $mailer->SMTPSecure = $config['encryption'] ?? 'tls';
        if (!empty($config['ca_file'])) {
            $mailer->SMTPOptions = ['ssl' => ['cafile' => $config['ca_file']]];
        }
        $mailer->setFrom($config['from'], 'Water Go');
        $mailer->addAddress($to);
        $mailer->CharSet = 'UTF-8';
        $mailer->Subject = $subject;
        $mailer->Body = $body;
        return $mailer->send();
    } catch (Throwable $e) {
        error_log('Water Go SMTP delivery failed: ' . $e->getMessage());
        return false;
    }
}

function auth_send_otp_email(string $email, string $subject, string $code, int $expiresAt): bool {
    $expiry = (new DateTimeImmutable('@' . $expiresAt))
        ->setTimezone(new DateTimeZone('Asia/Manila'))->format('g:i:s A');
    return auth_send_mail($email, 'Water Go - ' . $subject,
        "Your Water Go code is {$code}. It expires at {$expiry} Philippine time.\n\n"
        . 'If you did not request this code, ignore this email and consider changing your password.');
}

function auth_otp_table(string $purpose): string {
    return match ($purpose) {
        'login' => 'auth_login_otps',
        'reset' => 'password_reset_otps',
        'register' => 'registration_otps',
    };
}

function auth_issue_otp(PDO $pdo, string $purpose, array $account, string $typed, bool $resend = false): array {
    $table = auth_otp_table($purpose);
    $userId = (int)$account['id'];
    $code = sprintf('%06d', random_int(0, 999999));
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT id, email_verified, password FROM users WHERE id = ? FOR UPDATE');
        $stmt->execute([$userId]);
        $lockedUser = $stmt->fetch();
        if (!$lockedUser || ($purpose === 'register' && $lockedUser['email_verified'])
            || ($purpose !== 'register' && isset($account['password']) && $account['password'] !== $lockedUser['password'])) {
            $pdo->rollBack();
            return ['error' => 'Start again to request a new code.'];
        }
        $now = time();
        $expiresAt = $now + auth_settings()['otp_expiry_seconds'];
        $requestCount = $purpose === 'login' ? 'COALESCE(SUM(verified_at IS NULL), 0)' : 'COUNT(*)';
        $stmt = $pdo->prepare("SELECT $requestCount AS total, COALESCE(SUM(is_resend), 0) AS resends, MAX(created_at) AS latest
            FROM $table WHERE user_id = ? AND created_at > ?");
        $stmt->execute([$userId, gmdate('Y-m-d H:i:s', $now - 900)]);
        $recent = $stmt->fetch();
        $wait = $recent['latest'] ? max(0, strtotime($recent['latest'] . ' UTC') + 60 - $now) : 0;
        if ($wait && $purpose === 'login' && !$resend) {
            $stmt = $pdo->prepare('SELECT verified_at FROM auth_login_otps WHERE user_id = ? ORDER BY id DESC LIMIT 1');
            $stmt->execute([$userId]);
            if ($stmt->fetchColumn()) {
                $wait = 0;
            }
        }
        if ($wait || (int)$recent['total'] >= 4 || ($resend && (int)$recent['resends'] >= 3)) {
            $pdo->rollBack();
            return ['error' => $wait ? "Wait {$wait} seconds before requesting another code." : 'Too many code requests. Try again in 15 minutes.'];
        }
        $stmt = $pdo->prepare("UPDATE $table SET used_at = UTC_TIMESTAMP() WHERE user_id = ? AND used_at IS NULL");
        $stmt->execute([$userId]);
        $stmt = $pdo->prepare("INSERT INTO $table (user_id, code_hash, expires_at, request_ip, created_at, is_resend)
                              VALUES (?, ?, ?, ?, UTC_TIMESTAMP(), ?)");
        $stmt->execute([$userId, password_hash($code, PASSWORD_DEFAULT),
            gmdate('Y-m-d H:i:s', $expiresAt), auth_client_ip_binary(), (int)$resend]);
        $id = (int)$pdo->lastInsertId();
        $sent = auth_send_otp_email($account['email'], match ($purpose) { 'login' => 'Your log-in code', 'reset' => 'Password reset code', 'register' => 'Verify your account' }, $code, $expiresAt);
        if (!$sent) {
            $stmt = $pdo->prepare("UPDATE $table SET used_at = UTC_TIMESTAMP() WHERE id = ?");
            $stmt->execute([$id]);
        } else {
            auth_log_event($pdo, 'OTP_SENT', $typed, $userId, 'purpose=' . $purpose . '; resend=' . (int)$resend);
        }
        $pdo->commit();
        return $sent ? ['id' => $id, 'resend_at' => $now + 60, 'expires_at' => $expiresAt] :
            ['error' => 'We could not send the code. Try again later.'];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

function auth_verify_otp(PDO $pdo, string $purpose, array $pending, string $code): bool {
    $table = auth_otp_table($purpose);
    $limit = auth_settings()['otp_max_attempts'];
    $pdo->beginTransaction();
    try {
        if ($purpose === 'register') {
            $stmt = $pdo->prepare('SELECT id, email_verified, password FROM users WHERE id = ? FOR UPDATE');
            $stmt->execute([$pending['id']]);
        }
        $stmt = $pdo->prepare("SELECT code_hash, attempts FROM $table
            WHERE id = ? AND user_id = ? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP() AND attempts < ? FOR UPDATE");
        $stmt->execute([$pending['otp_id'], $pending['id'], $limit]);
        $row = $stmt->fetch();
        $valid = $row && preg_match('/^[0-9]{6}$/D', $code) && password_verify($code, $row['code_hash']);
        if ($row) {
            $attempts = (int)$row['attempts'] + (int)!$valid;
            $stmt = $pdo->prepare("UPDATE $table SET attempts = ?, used_at = IF(?, UTC_TIMESTAMP(), NULL) WHERE id = ?");
            $stmt->execute([$attempts, (int)($valid || $attempts >= $limit), $pending['otp_id']]);
            if ($valid && $purpose === 'login') {
                $stmt = $pdo->prepare('UPDATE auth_login_otps SET verified_at = UTC_TIMESTAMP() WHERE id = ?');
                $stmt->execute([$pending['otp_id']]);
            }
        }
        if ($valid && $purpose === 'register') {
            $stmt = $pdo->prepare('UPDATE users SET email_verified = 1 WHERE id = ? AND email_verified = 0');
            $stmt->execute([$pending['id']]);
            if ($stmt->rowCount()) {
                auth_log_event($pdo, 'ACCOUNT_VERIFIED', $pending['typed'], $pending['id'], 'purpose=registration');
            }
        }
        if (!$valid) {
            auth_log_event($pdo, 'OTP_FAILED', $pending['typed'], $pending['id'], 'purpose=' . $purpose);
        }
        $pdo->commit();
        return (bool)$valid;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

function auth_otp_input(array $pending): void {
    $now = time();
    $wait = max(0, (int)$pending['resend_at'] - $now);
    $hasCode = (int)$pending['otp_id'] > 0;
    $expires = (int)($pending['expires_at'] ?? ($pending['resend_at'] - 60 + auth_settings()['otp_expiry_seconds']));
    $remaining = max(0, $expires - $now);
    ?>
    <?php if ($hasCode): ?>
      <p class="otp-expiry" data-otp-seconds="<?= $remaining ?>">
        <?php if ($remaining > 0): ?>
          Code expires in <strong data-otp-time><?= sprintf('%d:%02d', intdiv($remaining, 60), $remaining % 60) ?></strong>
        <?php else: ?>
          Code expired. Request a new code.
        <?php endif; ?>
      </p>
    <?php endif; ?>
    <label for="otp">6-digit OTP <span class="required-mark">*</span></label>
    <input id="otp" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code">
    <button class="btn btn-primary submit-btn" name="action" value="verify">Verify code</button>
    <button class="btn" name="action" value="resend" formnovalidate data-resend-wait="<?= $wait ?>" <?= $wait ? 'disabled' : '' ?>>Resend OTP<?= $wait ? " ({$wait}s)" : '' ?></button>
    <?php
}
