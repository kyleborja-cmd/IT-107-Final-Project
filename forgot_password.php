<?php
require_once __DIR__ . '/includes/session_security.php';
require_once __DIR__ . '/includes/profile_validation.php';
require_once __DIR__ . '/includes/recaptcha.php';
require __DIR__ . '/config/database.php';

$csrf = auth_csrf_token('recover_csrf');
$labels = auth_settings()['security_questions'];
$pending = $_SESSION['recovery'] ?? null;
$identifier = is_string($_GET['identifier'] ?? null) ? $_GET['identifier'] : '';
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = registration_input('action');
    $ip = auth_client_ip_binary();
    if (!auth_valid_csrf('recover_csrf', registration_input('csrf_token'))) {
        auth_log_event($pdo, 'CSRF_REJECTED', null, null, 'purpose=reset');
        $error = 'Reload this page and try again.';
    } elseif (auth_ip_block_seconds($pdo, $ip)) {
        $error = 'Recovery is temporarily blocked from this IP address.';
    } elseif ($action === 'start') {
        $identifier = registration_input('identifier');
        if (recaptcha_verify_submission(registration_input('g-recaptcha-response')) !== 'verified') {
            auth_log_event($pdo, 'CAPTCHA_FAILED', $identifier, null, 'purpose=reset');
            $error = 'Complete the reCAPTCHA check and try again.';
        } elseif ($identifier === '') {
            $error = 'Enter your username or email.';
        } else {
            $account = auth_find_account($pdo, $identifier);
            $recoveryAnswers = $account ? registration_recovery_answers($pdo, $account) : [];
            $questions = array_keys($labels);
            $secret = $GLOBALS['waterGoPrivate']['encryption_key'] ?? $csrf;
            usort($questions, static fn($a, $b) => strcmp(
                hash_hmac('sha256', strtolower($identifier) . $a, $secret),
                hash_hmac('sha256', strtolower($identifier) . $b, $secret)
            ));
            $pending = [
                'typed' => $identifier, 'expires' => time() + 900,
                'questions' => $recoveryAnswers ? array_keys($recoveryAnswers) : array_slice($questions, 0, 3),
                'stage' => 'answer',
            ];
            unset($_SESSION['password_change']);
            $_SESSION['recovery'] = $pending;
            auth_log_event($pdo, 'RESET_REQUESTED', $identifier, $account ? (int)$account['id'] : null, 'purpose=reset');
        }
    } elseif ($pending && $pending['expires'] > time()) {
        $account = auth_find_account($pdo, $pending['typed']);
        $hash = $account ? auth_account_hash((int)$account['id']) : auth_identifier_hash($pending['typed']);
        if ((int)auth_get_login_state($pdo, $hash)['locked_seconds'] > 0) {
            $error = 'Too many failed sign-in attempts. Try again after the lockout.';
        } elseif ($action === 'answer' && $pending['stage'] === 'answer') {
            $answer = registration_input('answer');
            $question = registration_input('question');
            if ($answer !== registration_input('confirm_answer')) {
                $error = 'Answers do not match.';
            } else {
                $recoveryAnswers = $account ? registration_recovery_answers($pdo, $account) : [];
                $answerHash = in_array($question, $pending['questions'], true) ? ($recoveryAnswers[$question] ?? null) : null;
                $correct = password_verify(mb_strtolower($answer, 'UTF-8'), $answerHash ?? auth_dummy_hash());
                if (!$correct || !$answerHash || registration_security_answer_error($answer, 'Answer')) {
                    auth_log_event($pdo, 'LOGIN_FAILED', $pending['typed'], $account ? (int)$account['id'] : null, 'purpose=reset; answer_rejected');
                    auth_record_failure($pdo, $hash, $pending['typed'], $account, 'reset');
                    $error = 'The security answer could not be verified.';
                } else {
                    $issued = auth_issue_otp($pdo, 'reset', $account, $pending['typed']);
                    $error = $issued['error'] ?? '';
                    if (!$error) {
                        $pending = $_SESSION['recovery'] = array_merge($pending, [
                            'id' => (int)$account['id'], 'otp_id' => $issued['id'], 'resend_at' => $issued['resend_at'], 'expires_at' => $issued['expires_at'],
                            'stage' => 'otp', 'password' => $account['password'],
                        ]);
                    }
                }
            }
        } elseif ($pending['stage'] === 'otp' && $account && $pending['password'] === $account['password']) {
            if ($action === 'resend') {
                $issued = auth_issue_otp($pdo, 'reset', $account, $pending['typed'], true);
                $error = $issued['error'] ?? '';
                if (!$error) {
                    $pending['otp_id'] = $issued['id'];
                    $pending['resend_at'] = $issued['resend_at'];
                    $pending['expires_at'] = $issued['expires_at'];
                    $_SESSION['recovery'] = $pending;
                }
            } elseif ($action === 'verify' && auth_verify_otp($pdo, 'reset', $pending, registration_input('otp'))) {
                session_regenerate_id(true);
                $_SESSION['password_change'] = ['id' => $pending['id'], 'password' => $pending['password'], 'expires' => time() + 300];
                unset($_SESSION['recovery']);
                header('Location: reset_password.php');
                exit;
            } else {
                $error = 'The OTP is invalid, expired, or has already been used.';
            }
        }
    }
}
if (isset($_GET['restart']) || ($pending && $pending['expires'] <= time())) {
    unset($_SESSION['recovery']);
    $pending = null;
}
$pageTitle = 'Forgot password';
include __DIR__ . '/includes/header.php';
?>
<main class="login-form-inner security-form">
  <a class="login-back" href="login.php">&larr; Back to Log in</a>
  <h1>Forgot password?</h1>
  <?php if ($error && !$pending): ?><p class="alert-error" role="alert"><?= htmlspecialchars($error) ?></p><?php endif; ?>
  <form method="post" action="forgot_password.php" class="auth-form">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
    <?php if (!$pending): ?>
      <label for="identifier">Username or email <span class="required-mark">*</span></label>
      <input id="identifier" name="identifier" required maxlength="100" autocomplete="username" value="<?= htmlspecialchars($identifier) ?>">
      <?php recaptcha_render_widget(); ?>
      <button class="btn btn-primary" name="action" value="start">Continue</button>
    <?php elseif ($pending['stage'] === 'answer'): ?>
      <label for="question">Choose the following question <span class="required-mark">*</span></label>
      <select id="question" name="question" required>
        <?php foreach ($pending['questions'] as $question): ?>
          <?php if (isset($labels[$question])): ?><option value="<?= htmlspecialchars($question) ?>"><?= htmlspecialchars($labels[$question]) ?></option><?php endif; ?>
        <?php endforeach; ?>
      </select>
      <label for="answer">Your Answer <span class="required-mark">*</span></label>
      <input id="answer" name="answer" type="password" minlength="2" maxlength="50" required>
      <label for="confirm_answer">Re-enter Answer <span class="required-mark">*</span></label>
      <input id="confirm_answer" name="confirm_answer" type="password" minlength="2" maxlength="50" required>
      <?php if ($error): ?><small class="field-error" role="alert"><?= htmlspecialchars($error) ?></small><?php endif; ?>
      <button class="btn btn-primary" name="action" value="answer">Verify answer</button>
    <?php else: ?>
      <p>Enter the code sent to your registered email.</p>
      <?php auth_otp_input($pending); ?>
      <?php if ($error): ?><small class="field-error" role="alert"><?= htmlspecialchars($error) ?></small><?php endif; ?>
    <?php endif; ?>
  </form>
  <?php if ($pending): ?><p><a href="forgot_password.php?restart=1">Start over</a></p><?php endif; ?>
</main>
<?php include __DIR__ . '/includes/footer.php'; ?>
