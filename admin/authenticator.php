<?php
require __DIR__ . '/../includes/session_security.php';
require_role('admin');
require __DIR__ . '/../includes/profile_validation.php';
require __DIR__ . '/../includes/admin_totp.php';

$pdo = $GLOBALS['pdo'];
$user = $_SESSION['user'];
$id = (int)$user['id'];
$stmt = $pdo->prepare('SELECT admin_username, (admin_totp_secret IS NOT NULL) AS enabled FROM users WHERE id = ?');
$stmt->execute([$id]);
$config = $stmt->fetch();
$enabled = (bool)$config['enabled'];
$csrf = auth_csrf_token('admin_totp_csrf');
$pending = $_SESSION['admin_totp_setup'] ?? null;
if ($enabled || ($pending && ($pending['id'] !== $id || $pending['expires'] <= time()))) {
    unset($_SESSION['admin_totp_setup']);
    $pending = null;
}
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$enabled) {
    $identifier = (string)($config['admin_username'] ?: $user['email']);
    $accountHash = auth_account_hash($id);
    if (!auth_valid_csrf('admin_totp_csrf', registration_raw_input('csrf_token'))) {
        auth_log_event($pdo, 'CSRF_REJECTED', $identifier, $id, 'purpose=admin_authenticator');
        http_response_code(403);
        $error = 'Reload this page and try again.';
    } elseif (auth_ip_block_seconds($pdo, auth_client_ip_binary())
        || (int)auth_get_login_state($pdo, $accountHash)['locked_seconds'] > 0) {
        $error = 'Authenticator setup is temporarily blocked.';
    } elseif (!$config['admin_username']) {
        $error = 'An admin username is required before setting up the authenticator.';
    } else {
        $stmt = $pdo->prepare('SELECT password FROM users WHERE id = ? AND role = ? AND email_verified = 1');
        $stmt->execute([$id, 'admin']);
        $hash = $stmt->fetchColumn();
        if (!is_string($hash) || !password_verify(registration_raw_input('current_password'), $hash)) {
            auth_log_event($pdo, 'LOGIN_FAILED', $identifier, $id, 'purpose=admin_authenticator');
            auth_record_failure($pdo, $accountHash, $identifier, $user, 'admin_authenticator');
            $error = 'The current password is incorrect.';
        } elseif (!$pending && registration_input('action') === 'start') {
            $_SESSION['admin_totp_setup'] = ['id' => $id, 'secret' => random_bytes(20), 'expires' => time() + 300, 'attempts' => 0];
            header('Location: authenticator.php', true, 303);
            exit;
        } elseif ($pending && registration_input('action') === 'verify') {
            $step = admin_totp_match($pending['secret'], registration_input('otp'));
            if ($step === null) {
                auth_log_event($pdo, 'OTP_FAILED', $identifier, $id, 'purpose=admin_authenticator_setup');
                if (++$_SESSION['admin_totp_setup']['attempts'] >= auth_settings()['otp_max_attempts']) {
                    unset($_SESSION['admin_totp_setup']);
                    $pending = null;
                }
                $error = 'That code did not match.';
            } else {
                $stmt = $pdo->prepare('UPDATE users SET admin_totp_secret = ?, admin_totp_last_step = ?
                    WHERE id = ? AND role = ? AND email_verified = 1 AND password = ? AND admin_totp_secret IS NULL');
                $stmt->execute([admin_totp_encrypt($pending['secret']), $step, $id, 'admin', $hash]);
                if ($stmt->rowCount()) {
                    auth_log_event($pdo, 'ADMIN_AUTHENTICATOR_ENABLED', $identifier, $id, '');
                }
                unset($_SESSION['admin_totp_setup']);
                header('Location: authenticator.php', true, 303);
                exit;
            }
        } else {
            $error = 'The setup expired. Start again.';
        }
    }
}
$pageTitle = 'Admin authenticator';
include __DIR__ . '/../includes/header.php';
?>
<main class="login-form-inner security-form">
  <a class="login-back" href="settings.php">Back to Settings</a>
  <h1>Authenticator app</h1>
  <?php if ($enabled): ?>
    <p class="alert-success" role="status">Authenticator enabled. Use your app for the next admin sign-in. If you lose the device, contact your system operator.</p>
  <?php else: ?>
    <?php if ($error): ?><p class="alert-error" role="alert"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    <?php if ($pending): ?>
      <p>In your authenticator app, add a time-based account named <strong>Water Go</strong> and enter this setup key.</p>
      <p><code><?= htmlspecialchars(admin_totp_setup_key($pending['secret'])) ?></code></p>
      <p>Keep the setup key private.</p>
    <?php else: ?>
      <p>Confirm your password to set up an app that generates your sign-in codes.</p>
    <?php endif; ?>
    <form method="post" class="auth-form">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
      <label for="current_password">Current admin password</label>
      <input id="current_password" name="current_password" type="password" autocomplete="current-password" required>
      <?php if ($pending): ?>
        <label for="otp">Six-digit code from your app</label>
        <input id="otp" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required>
      <?php endif; ?>
      <button class="btn btn-primary submit-btn" name="action" value="<?= $pending ? 'verify' : 'start' ?>" type="submit"><?= $pending ? 'Enable authenticator' : 'Get setup key' ?></button>
    </form>
  <?php endif; ?>
</main>
<?php include __DIR__ . '/../includes/footer.php'; ?>
