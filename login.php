<?php
require_once __DIR__ . '/includes/session_security.php';
require_once __DIR__ . '/includes/recaptcha.php';
require_once __DIR__ . '/includes/admin_totp.php';
require __DIR__ . '/config/database.php';

if (isset($_GET['idle']) && !empty($_SESSION['user']) &&
    time() - (int)($_SESSION['last_activity'] ?? 0) >= auth_settings()['idle_session_timeout_seconds']) {
    $_SESSION = [];
    session_regenerate_id(true);
    $_SESSION['auth_notice'] = 'Your session expired due to inactivity.';
}
if (!empty($_SESSION['user'])) {
    header('Location: dashboard.php');
    exit;
}
if (isset($_GET['restart'])) {
    unset($_SESSION['pending_login']);
    header('Location: login.php');
    exit;
}
$settings = auth_settings();
$stmt = $pdo->prepare('DELETE FROM auth_login_attempts WHERE attempt_at < ?');
$stmt->execute([gmdate('Y-m-d H:i:s', time() - $settings['login_attempt_retention_seconds'])]);
$error = '';
$notice = $_SESSION['auth_notice'] ?? '';
unset($_SESSION['auth_notice']);
$pendingLogin = $_SESSION['pending_login'] ?? null;
$otpStage = isset($pendingLogin['id']);
$authenticatorStage = ($pendingLogin['method'] ?? '') === 'authenticator';
if (!$otpStage) {
    unset($_SESSION['pending_login']);
}
$usernameRaw = is_string($_POST['username'] ?? null) ? $_POST['username'] : ($_SESSION['last_login_identifier'] ?? '');
$identifier = trim($usernameRaw);
$usernameTyped = $usernameRaw;
$password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
$csrfToken = auth_csrf_token('login_csrf');
$cooldownSeconds = 0;
$ip = auth_client_ip_binary();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if (!auth_valid_csrf('login_csrf', is_string($_POST['csrf_token'] ?? null) ? $_POST['csrf_token'] : '')) {
        auth_log_event($pdo, 'CSRF_REJECTED', $usernameTyped, null, 'purpose=login');
        $error = 'Your sign-in form expired. Reload the page and try again.';
    } elseif (auth_ip_block_seconds($pdo, $ip) > 0) {
        $error = 'Sign-in is temporarily blocked from this IP address.';
    } elseif ($otpStage) {
        $state = auth_get_login_state($pdo, auth_account_hash($pendingLogin['id']));
        $code = is_string($_POST['otp'] ?? null) ? trim($_POST['otp']) : '';
        if ((int)$state['locked_seconds'] > 0) {
            $error = 'Too many failed sign-in attempts.';
        } elseif ($authenticatorStage && time() >= $pendingLogin['expires']) {
            unset($_SESSION['pending_login']);
            $otpStage = false;
            $error = 'Your sign-in expired. Enter your credentials again.';
        } elseif ($action === 'resend' && !$authenticatorStage) {
            $issued = auth_issue_otp($pdo, 'login', $pendingLogin, $pendingLogin['typed'], true);
            $error = $issued['error'] ?? '';
            if (!$error) {
                $pendingLogin['otp_id'] = $issued['id'];
                $pendingLogin['resend_at'] = $issued['resend_at'];
                $pendingLogin['expires_at'] = $issued['expires_at'];
                $_SESSION['pending_login'] = $pendingLogin;
                $notice = 'A new code was sent.';
            }
        } elseif ($action === 'verify' && ($authenticatorStage
            ? admin_totp_verify_login($pdo, $pendingLogin, $code)
            : auth_verify_otp($pdo, 'login', $pendingLogin, $code))) {
            $stmt = $pdo->prepare('SELECT u.id, COALESCE(u.admin_username, p.username) AS username, u.email, u.full_name, u.role
                FROM users u LEFT JOIN staff_registration_profiles p ON p.user_id = u.id
                WHERE u.id = ? AND u.password = ? AND u.email_verified = 1
                AND (u.admin_totp_secret IS NOT NULL) = ?');
            $stmt->execute([$pendingLogin['id'], $pendingLogin['password'], (int)$authenticatorStage]);
            $user = $stmt->fetch();
            unset($_SESSION['pending_login']);
            if ($user) {
                auth_delete_login_states($pdo, [auth_account_hash($pendingLogin['id'])]);
                session_regenerate_id(true);
                $_SESSION['user'] = $user;
                $_SESSION['login_otp_verified'] = true;
                $_SESSION['last_activity'] = time();
                auth_log_event($pdo, 'LOGIN_SUCCESS', $pendingLogin['typed'], $pendingLogin['id'], 'login_otp_verified');
                header('Location: dashboard.php');
                exit;
            }
            $otpStage = false;
            $error = 'Your sign-in expired. Enter your credentials again.';
        } else {
            $error = 'The OTP is invalid, expired, or has already been used.';
            if ($authenticatorStage && $action === 'verify') {
                auth_log_event($pdo, 'OTP_FAILED', $pendingLogin['typed'], $pendingLogin['id'], 'purpose=login; method=authenticator');
                $account = auth_find_account($pdo, $pendingLogin['typed']);
                auth_record_failure($pdo, auth_account_hash($pendingLogin['id']), $pendingLogin['typed'], $account, 'login_authenticator');
                if (++$_SESSION['pending_login']['attempts'] >= $settings['otp_max_attempts']) {
                    unset($_SESSION['pending_login']);
                    $otpStage = false;
                    $error = 'Enter your username and password to start a new sign-in.';
                }
            }
        }
    } elseif (($captcha = recaptcha_verify_submission(is_string($_POST['g-recaptcha-response'] ?? null) ? $_POST['g-recaptcha-response'] : '')) !== 'verified') {
        auth_log_event($pdo, 'CAPTCHA_FAILED', $usernameTyped, null, 'purpose=login; status=' . $captcha);
        $error = 'Complete the reCAPTCHA check and try again.';
    } else {
        $_SESSION['last_login_identifier'] = mb_substr($usernameRaw, 0, 100);
        $account = auth_find_account($pdo, $identifier);
        $hash = $account ? auth_account_hash((int)$account['id']) : auth_identifier_hash($identifier);
        $state = auth_get_login_state($pdo, $hash);
        $cooldownSeconds = (int)$state['locked_seconds'];
        if ($cooldownSeconds > 0) {
            $error = 'Too many failed sign-in attempts.';
        } else {
            $correct = password_verify($password, $account['password'] ?? auth_dummy_hash());
            $validIdentifier = auth_valid_username($identifier)
                && $account && strcasecmp($identifier, (string)$account['username']) === 0;
            if ($account && $correct && $validIdentifier && mb_strlen($password) >= $settings['password_min_length'] && mb_strlen($password) <= $settings['password_max_length']) {
                $authenticatorStage = $account['role'] === 'admin' && (bool)$account['has_authenticator'];
                $issued = $authenticatorStage
                    ? ['method' => 'authenticator', 'expires' => time() + $settings['otp_expiry_seconds'], 'attempts' => 0]
                    : auth_issue_otp($pdo, 'login', $account, $usernameTyped);
                $error = $issued['error'] ?? '';
                if (!$error) {
                    unset($_SESSION['last_login_identifier']);
                    $pendingLogin = $_SESSION['pending_login'] = [
                        'id' => (int)$account['id'], 'email' => $account['email'], 'password' => $account['password'],
                        'typed' => $usernameTyped,
                    ] + ($authenticatorStage ? $issued : ['otp_id' => $issued['id'], 'resend_at' => $issued['resend_at'], 'expires_at' => $issued['expires_at']]);
                    $otpStage = true;
                }
            } else {
                auth_log_event($pdo, 'LOGIN_FAILED', $usernameTyped, $account ? (int)$account['id'] : null, 'password_rejected');
                auth_record_failure($pdo, $hash, $usernameTyped, $account, 'login');
                $error = 'Invalid username or password.';
            }
        }
        $state = auth_get_login_state($pdo, $hash);
        $cooldownSeconds = (int)$state['locked_seconds'];
        if ($cooldownSeconds > 0 && $error === '') {
            $error = 'Too many failed sign-in attempts.';
        }
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !$otpStage && $identifier !== '') {
    $account = auth_find_account($pdo, $identifier);
    $state = auth_get_login_state($pdo, $account ? auth_account_hash((int)$account['id']) : auth_identifier_hash($identifier));
    $cooldownSeconds = (int)$state['locked_seconds'];
    if ($cooldownSeconds > 0) {
        $error = 'Too many failed sign-in attempts.';
    }
}
$ipCooldownSeconds = auth_ip_block_seconds($pdo, $ip);
if ($ipCooldownSeconds > 0) {
    $error = 'Sign-in is temporarily blocked from this IP address.';
    $cooldownSeconds = max($cooldownSeconds, $ipCooldownSeconds);
}
$cooldownActive = $cooldownSeconds > 0;

$pageTitle = 'Sign in';
include 'includes/header.php';
?>
<div class="login-page">
  <a class="login-back" href="index.php">← Back to home</a>
  <div class="login-shell">
    <div class="login-art">
      <a class="brand brand-on-dark" href="index.php"><span class="brand-mark">W</span><span>water<span class="brand-light">go</span><small>PURE WATER. EASY LIVING.</small></span></a>
    </div>
    <div class="login-form-wrap">
      <div class="login-form-inner">
        <div class="eyebrow">WATER GO PORTAL</div><h2><?= $otpStage ? 'Verify your sign-in' : 'Sign in' ?></h2><p class="muted"><?= $otpStage ? ($authenticatorStage ? 'Enter the six-digit code from your authenticator app.' : 'Enter the six-digit code sent to ' . htmlspecialchars((string)$pendingLogin['email'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '.') : 'Enter your username and password to continue.' ?></p>
        <?php if ($notice): ?><div class="alert-success" role="status"><?= htmlspecialchars($notice, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></div><?php endif; ?>
        <?php if ($error && ($error !== 'Invalid username or password.' || $cooldownActive)): ?><div class="alert-error" role="alert"><?= htmlspecialchars($error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?><?php if ($cooldownActive): ?><span data-login-cooldown="<?= $cooldownSeconds ?>" role="timer" aria-live="off"> Try again in <strong data-cooldown-remaining><?= $cooldownSeconds ?></strong> seconds.</span><?php endif; ?></div><?php endif; ?>
        <form method="POST" class="auth-form login-fields">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
          <?php if ($otpStage && $authenticatorStage): ?>
          <label for="authenticator-otp">Authenticator code</label>
          <input id="authenticator-otp" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required>
          <button class="btn btn-primary submit-btn" name="action" value="verify" type="submit">Verify code</button>
          <?php elseif ($otpStage): ?>
          <?php auth_otp_input($pendingLogin); ?>
          <?php else: ?>
          <label for="username">Username</label><input id="username" type="text" name="username" placeholder="Your username" maxlength="100" required autocomplete="username" value="<?= htmlspecialchars($usernameRaw, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
          <div class="password-label"><label for="password">Password</label></div>
          <div class="password-field"><input id="password" type="password" name="password" placeholder="Enter your password" required autocomplete="current-password"><button type="button" class="toggle-password" aria-label="Show password">◉</button></div>
          <?php if ($error === 'Invalid username or password.' && !$cooldownActive): ?><small class="field-error" role="alert"><?= htmlspecialchars($error) ?></small><?php endif; ?>
          <?php recaptcha_render_widget(); ?>
          <button name="action" value="credentials" class="btn btn-primary submit-btn" id="login-submit" type="submit" <?= $cooldownActive ? 'disabled' : '' ?>>Sign in <span>→</span></button>
          <?php endif; ?>
        </form>
        <?php if ($otpStage): ?><p class="forgot-password-link"><a href="login.php?restart=1">Start over</a></p><?php else: ?><p class="forgot-password-link"><a href="forgot_password.php?identifier=<?= rawurlencode($identifier) ?>">Forgot Password? Reset Here</a></p><?php endif; ?>
        <div class="login-note"><span>♢</span> Secure access for authorized Water Go personnel. <a data-register-link <?= $cooldownActive ? 'aria-disabled="true"' : 'href="register.php"' ?>>Please register here</a></div>
        <a class="back-home-mobile" href="index.php">← Back to homepage</a>
      </div>
    </div>
  </div>
</div>
<?php include 'includes/footer.php'; ?>
