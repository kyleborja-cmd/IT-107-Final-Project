<?php

function admin_totp_setup_key(string $secret): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $key = '';
    $bits = 0;
    $buffer = 0;
    foreach (unpack('C*', $secret) as $byte) {
        $buffer = ($buffer << 8) | $byte;
        $bits += 8;
        while ($bits >= 5) {
            $bits -= 5;
            $key .= $alphabet[($buffer >> $bits) & 31];
        }
        $buffer &= (1 << $bits) - 1;
    }
    return $bits ? $key . $alphabet[($buffer << (5 - $bits)) & 31] : $key;
}

function admin_totp_code(string $secret, int $step): string {
    $digest = hash_hmac('sha1', pack('N2', 0, $step), $secret, true);
    $offset = ord($digest[19]) & 15;
    $number = unpack('N', substr($digest, $offset, 4))[1] & 0x7fffffff;
    return sprintf('%06d', $number % 1000000);
}

function admin_totp_match(string $secret, string $code): ?int {
    if (!preg_match('/^[0-9]{6}$/D', $code)) {
        return null;
    }
    $current = intdiv(time(), 30);
    foreach ([$current, $current - 1, $current + 1] as $step) {
        if (hash_equals(admin_totp_code($secret, $step), $code)) {
            return $step;
        }
    }
    return null;
}

function admin_totp_encrypt(string $secret): string {
    $key = admin_totp_encryption_key();
    $iv = random_bytes(12);
    $encrypted = openssl_encrypt($secret, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, 'admin-totp', 16);
    if ($encrypted === false) {
        throw new RuntimeException('Could not encrypt authenticator secret.');
    }
    return base64_encode($iv . $tag . $encrypted);
}

function admin_totp_encryption_key(): string {
    $key = base64_decode($GLOBALS['waterGoPrivate']['encryption_key'] ?? '', true);
    if ($key === false || strlen($key) !== 32) {
        throw new RuntimeException('Configure the Water Go encryption key for the authenticator.');
    }
    return hash_hmac('sha256', 'water-go-admin-totp-v1', $key, true);
}

function admin_totp_verify_login(PDO $pdo, array $pending, string $code): bool {
    $stmt = $pdo->prepare('SELECT admin_totp_secret FROM users
        WHERE id = ? AND role = ? AND email_verified = 1 AND password = ?');
    $stmt->execute([$pending['id'], 'admin', $pending['password']]);
    $stored = $stmt->fetchColumn();
    $bytes = $stored ? base64_decode($stored, true) : false;
    if ($bytes === false || strlen($bytes) !== 48) {
        return false;
    }
    $secret = openssl_decrypt(substr($bytes, 28), 'aes-256-gcm', admin_totp_encryption_key(), OPENSSL_RAW_DATA,
        substr($bytes, 0, 12), substr($bytes, 12, 16), 'admin-totp');
    $step = $secret === false ? null : admin_totp_match($secret, $code);
    if ($step === null) {
        return false;
    }
    $stmt = $pdo->prepare('UPDATE users SET admin_totp_last_step = ?
        WHERE id = ? AND role = ? AND email_verified = 1 AND password = ? AND admin_totp_secret = ?
        AND (admin_totp_last_step IS NULL OR admin_totp_last_step < ?)');
    $stmt->execute([$step, $pending['id'], 'admin', $pending['password'], $stored, $step]);
    return $stmt->rowCount() === 1;
}
