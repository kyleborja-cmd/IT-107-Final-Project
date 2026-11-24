<?php
require __DIR__ . '/../includes/session_security.php';
require_role('admin');
require __DIR__ . '/../includes/profile_validation.php';

$pdo = $GLOBALS['pdo'];
$user = $_SESSION['user'];
$id = (int)$user['id'];
$typed = (string)($user['username'] ?? $user['email']);
$questions = auth_settings()['security_questions'];
$csrf = auth_csrf_token('admin_recovery_csrf');
$error = '';
$saved = !empty($_SESSION['admin_recovery_saved']);
unset($_SESSION['admin_recovery_saved']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $hash = auth_account_hash($id);
    if (!auth_valid_csrf('admin_recovery_csrf', registration_raw_input('csrf_token'))) {
        auth_log_event($pdo, 'CSRF_REJECTED', $typed, $id, 'purpose=admin_recovery');
        http_response_code(403);
        $error = 'Reload this page and try again.';
    } elseif (auth_ip_block_seconds($pdo, auth_client_ip_binary()) || (int)auth_get_login_state($pdo, $hash)['locked_seconds'] > 0) {
        $error = 'Recovery changes are temporarily blocked. Try again after the cooldown.';
    } else {
        $selections = $answers = [];
        for ($i = 1; $i <= 3; $i++) {
            $question = registration_input("question_$i");
            $answer = registration_input("answer_$i");
            if (!isset($questions[$question]) || isset($selections[$question])) {
                $error = 'Choose three different questions.';
                break;
            }
            $error = registration_security_answer_error($answer, "Answer $i") ?? '';
            if ($error !== '') {
                break;
            }
            $selections[$question] = true;
            $answers[$question] = mb_strtolower($answer, 'UTF-8');
        }

        if ($error === '') {
            $pdo->beginTransaction();
            try {
                $stmt = $pdo->prepare('SELECT password FROM users WHERE id = ? AND role = ? AND email_verified = 1 FOR UPDATE');
                $stmt->execute([$id, 'admin']);
                $passwordHash = $stmt->fetchColumn();
                if (!is_string($passwordHash) || !password_verify(registration_raw_input('current_password'), $passwordHash)) {
                    $pdo->rollBack();
                    auth_log_event($pdo, 'LOGIN_FAILED', $typed, $id, 'purpose=admin_recovery; password_rejected');
                    auth_record_failure($pdo, $hash, $typed, $user, 'admin_recovery');
                    $error = 'The current password is incorrect.';
                } else {
                    $stmt = $pdo->prepare('DELETE FROM admin_recovery_questions WHERE user_id = ?');
                    $stmt->execute([$id]);
                    $stmt = $pdo->prepare('INSERT INTO admin_recovery_questions (user_id, question_id, answer_hash) VALUES (?, ?, ?)');
                    foreach ($answers as $question => $answer) {
                        $stmt->execute([$id, $question, password_hash($answer, PASSWORD_DEFAULT)]);
                    }
                    $stmt = $pdo->prepare('UPDATE password_reset_otps SET used_at = UTC_TIMESTAMP() WHERE user_id = ? AND used_at IS NULL');
                    $stmt->execute([$id]);
                    auth_log_event($pdo, 'RECOVERY_QUESTIONS_UPDATED', $typed, $id, 'role=admin');
                    $pdo->commit();
                    $_SESSION['admin_recovery_saved'] = true;
                    header('Location: recovery_setup.php', true, 303);
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
}

$enrolled = registration_recovery_answers($pdo, $user) !== [];
$pageTitle = 'Admin recovery questions';
include __DIR__ . '/../includes/header.php';
?>
<main class="login-form-inner security-form">
  <a class="login-back" href="dashboard.php">Back to admin dashboard</a>
  <h1>Recovery questions</h1>
  <p class="muted"><?= $enrolled ? 'Recovery questions are configured. Submit three questions and answers to replace them.' : 'Choose three different questions so you can reset your admin password.' ?></p>
  <?php if ($saved): ?><p class="alert-success" role="status">Recovery questions saved.</p><?php endif; ?>
  <?php if ($error): ?><p class="alert-error" role="alert"><?= htmlspecialchars($error) ?></p><?php endif; ?>
  <form method="post" class="auth-form">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
    <label for="current_password">Current admin password</label>
    <input id="current_password" name="current_password" type="password" required autocomplete="current-password">
    <?php for ($i = 1; $i <= 3; $i++): ?>
      <label for="question_<?= $i ?>">Question <?= $i ?></label>
      <select id="question_<?= $i ?>" name="question_<?= $i ?>" required>
        <option value="">Choose a question</option>
        <?php foreach ($questions as $key => $label): ?>
          <option value="<?= htmlspecialchars($key) ?>"<?= registration_input("question_$i") === $key ? ' selected' : '' ?>><?= htmlspecialchars($label) ?></option>
        <?php endforeach; ?>
      </select>
      <label for="answer_<?= $i ?>">Answer <?= $i ?></label>
      <input id="answer_<?= $i ?>" name="answer_<?= $i ?>" type="password" minlength="2" maxlength="50" required autocomplete="off">
    <?php endfor; ?>
    <button class="btn btn-primary submit-btn" type="submit">Save recovery questions</button>
  </form>
</main>
<?php include __DIR__ . '/../includes/footer.php'; ?>
