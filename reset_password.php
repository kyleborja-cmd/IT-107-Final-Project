<?php
require_once __DIR__ . '/includes/session_security.php';
require_once __DIR__ . '/includes/profile_validation.php';
$grant = $_SESSION['password_change'] ?? null;
if (!$grant || $grant['expires'] <= time()) {
    unset($_SESSION['password_change']);
    header('Location: forgot_password.php');
    exit;
}
require __DIR__ . '/config/database.php';
$settings = auth_settings();
$csrf = auth_csrf_token('change_csrf');
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = registration_raw_input('password');
    if (!auth_valid_csrf('change_csrf', registration_input('csrf_token'))) {
        auth_log_event($pdo, 'CSRF_REJECTED', null, $grant['id'], 'purpose=change_password');
        $error = 'Reload the form and try again.';
    } elseif (auth_ip_block_seconds($pdo, auth_client_ip_binary())) {
        $error = 'Recovery is temporarily blocked from this IP address.';
    } elseif ($password !== registration_raw_input('confirm_password')) {
        $error = 'Mismatch Password.';
    } elseif (registration_length($password) < $settings['password_min_length'] || registration_length($password) > $settings['password_max_length']) {
        $error = 'Password must contain 8 to 64 characters.';
    } elseif (registration_password_strength($password) === 'Weak') {
        $error = 'Password is weak. Use at least 8 characters and mix at least two character types.';
    } else {
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare('SELECT email, password FROM users WHERE id = ? FOR UPDATE');
            $stmt->execute([$grant['id']]);
            $user = $stmt->fetch();
            if (!$user || $user['password'] !== $grant['password']) {
                $pdo->rollBack();
                unset($_SESSION['password_change']);
                header('Location: forgot_password.php');
                exit;
            }
            if (!auth_save_new_password($pdo, (int)$grant['id'], $user['password'], $password)) {
                $pdo->rollBack();
                $error = 'You cannot reuse a recent password.';
            } else {
                auth_delete_login_states($pdo, [auth_account_hash($grant['id'])]);
                auth_log_event($pdo, 'PASSWORD_CHANGED', null, $grant['id'], 'purpose=reset');
                $pdo->commit();
                unset($_SESSION['password_change']);
                auth_send_security_alert($pdo, 'Your password was changed', 'Your Water Go account password was changed.', null, $grant['id'], $user['email']);
                $_SESSION['auth_notice'] = 'Successfully Change Password.';
                header('Location: login.php');
                exit;
            }
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }
}
$pageTitle = 'Change Password';
include __DIR__ . '/includes/header.php';
?>
<main class="login-form-inner security-form">
  <h1>Change Password</h1>
  <form method="post" class="auth-form" data-password-strength-form>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
    <label for="password">Enter Password <span class="required-mark">*</span></label>
    <input id="password" name="password" type="password" minlength="8" maxlength="64" required autocomplete="new-password">
    <meter id="password-meter" min="0" max="2" value="0" aria-label="Password strength"></meter>
    <small id="password-strength" aria-live="polite">Password strength: Weak</small>
    <?php if ($error && $error !== 'Mismatch Password.'): ?><small class="field-error" role="alert"><?= htmlspecialchars($error) ?></small><?php endif; ?>
    <label for="confirm_password">Re-enter Password <span class="required-mark">*</span></label>
    <input id="confirm_password" name="confirm_password" type="password" minlength="8" maxlength="64" required autocomplete="new-password">
    <?php if ($error === 'Mismatch Password.'): ?><small class="field-error" role="alert"><?= htmlspecialchars($error) ?></small><?php endif; ?>
    <button class="btn btn-primary" type="submit">Change Password</button>
  </form>
</main>
<?php include __DIR__ . '/includes/footer.php'; ?>
