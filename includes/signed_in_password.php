<?php

function auth_handle_signed_in_password_change(PDO $pdo, array $user, string $csrfKey): string {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return '';
    }
    $settings = auth_settings();
    $userId = (int)$user['id'];
    $identifier = (string)($user['username'] ?? $user['email']);
    $purpose = 'purpose=' . $user['role'] . '_change_password';
    $error = '';
    $password = registration_raw_input('password');
    $accountHash = auth_account_hash($userId);
    if (!auth_valid_csrf($csrfKey, registration_raw_input('csrf_token'))) {
        auth_log_event($pdo, 'CSRF_REJECTED', $identifier, $userId, $purpose);
        http_response_code(403);
        $error = 'Reload this page and try again.';
    } elseif (auth_ip_block_seconds($pdo, auth_client_ip_binary())
        || (int)auth_get_login_state($pdo, $accountHash)['locked_seconds'] > 0) {
        $error = 'Password changes are temporarily blocked. Try again after the cooldown.';
    } elseif ($password !== registration_raw_input('confirm_password')) {
        $error = 'The new passwords do not match.';
    } elseif (registration_length($password) < $settings['password_min_length']
        || registration_length($password) > $settings['password_max_length']) {
        $error = 'Use ' . $settings['password_min_length'] . ' to ' . $settings['password_max_length'] . ' characters.';
    } elseif (registration_password_strength($password) === 'Weak') {
        $error = 'Choose a password with at least two character types.';
    } else {
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare('SELECT password FROM users WHERE id = ? AND role = ? AND email_verified = 1 FOR UPDATE');
            $stmt->execute([$userId, $user['role']]);
            $currentHash = $stmt->fetchColumn();
            if (!is_string($currentHash) || !password_verify(registration_raw_input('current_password'), $currentHash)) {
                $pdo->rollBack();
                auth_log_event($pdo, 'LOGIN_FAILED', $identifier, $userId, $purpose . '; password_rejected');
                auth_record_failure($pdo, $accountHash, $identifier, $user, $user['role'] . '_change_password');
                $error = 'The current password is incorrect.';
            } elseif (!auth_save_new_password($pdo, $userId, $currentHash, $password)) {
                $pdo->rollBack();
                $error = 'You cannot reuse a recent password.';
            } else {
                auth_delete_login_states($pdo, [$accountHash]);
                auth_log_event($pdo, 'PASSWORD_CHANGED', $identifier, $userId, $purpose);
                $pdo->commit();
                $_SESSION = [];
                session_regenerate_id(true);
                $_SESSION['auth_notice'] = 'Password changed. Sign in again with your new password and verification code.';
                auth_send_security_alert($pdo, 'Your password was changed', 'Your Water Go password was changed.', $identifier, $userId, $user['email']);
                header('Location: ../login.php', true, 303);
                exit;
            }
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }
    return $error;
}
