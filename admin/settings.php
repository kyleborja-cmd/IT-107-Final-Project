<?php
require __DIR__ . '/../includes/session_security.php';
require_role('admin');
require __DIR__ . '/../includes/profile_validation.php';
require __DIR__ . '/../includes/signed_in_password.php';

$pdo = $GLOBALS['pdo'];
$user = $_SESSION['user'];
$userId = (int)$user['id'];
$settings = auth_settings();
$csrf = auth_csrf_token('admin_password_csrf');
$error = auth_handle_signed_in_password_change($pdo, $user, 'admin_password_csrf');

$recoveryReady = count(registration_recovery_answers($pdo, $user)) === 3;
$stmt = $pdo->prepare('SELECT admin_username, (admin_totp_secret IS NOT NULL) AS enabled FROM users WHERE id = ?');
$stmt->execute([$userId]);
$authenticator = $stmt->fetch();
$pageTitle = 'Admin settings';
include __DIR__ . '/../includes/header.php';
?>
<main class="dash-content admin-settings">
  <a class="btn admin-settings-back" href="dashboard.php"><span aria-hidden="true">&larr;</span> Back to Dashboard</a>
  <h1>Settings</h1>
  <div class="admin-settings-grid">
    <section class="content-panel admin-settings-panel">
      <h2>Account</h2>
      <dl>
        <div><dt>Name</dt><dd><?= htmlspecialchars((string)$user['full_name']) ?></dd></div>
        <div><dt>Email</dt><dd><?= htmlspecialchars((string)$user['email']) ?></dd></div>
        <div><dt>Role</dt><dd>Administrator</dd></div>
        <div><dt>Username</dt><dd><?= htmlspecialchars((string)$authenticator['admin_username']) ?></dd></div>
        <div><dt>Authenticator</dt><dd><?= $authenticator['enabled'] ? 'Enabled' : 'Not configured' ?></dd></div>
        <div><dt>Recovery questions</dt><dd><?= $recoveryReady ? 'Configured' : 'Not configured' ?></dd></div>
      </dl>
      <a class="btn btn-secondary" href="recovery_setup.php"><?= $recoveryReady ? 'Update recovery questions' : 'Set up recovery questions' ?></a>
      <a class="btn btn-secondary" href="authenticator.php">Authenticator app</a>
    </section>
    <section class="content-panel admin-settings-panel">
      <h2>Security limits</h2>
      <dl>
        <div><dt>Idle session timeout</dt><dd><?= (int)$settings['idle_session_timeout_seconds'] ?> seconds</dd></div>
        <div><dt>OTP expiry</dt><dd><?= (int)$settings['otp_expiry_seconds'] ?> seconds</dd></div>
        <div><dt>Incorrect OTP attempts</dt><dd><?= (int)$settings['otp_max_attempts'] ?></dd></div>
        <div><dt>Lockout tiers</dt><dd><?= htmlspecialchars(implode(' / ', $settings['lockout_tiers_seconds'])) ?> seconds</dd></div>
        <div><dt>Failures per lockout tier</dt><dd><?= (int)$settings['lockout_attempts'] ?></dd></div>
        <div><dt>IP block threshold</dt><dd><?= (int)$settings['ip_block_threshold'] ?> failures in <?= (int)$settings['ip_block_window_seconds'] ?> seconds</dd></div>
        <div><dt>IP block duration</dt><dd><?= (int)$settings['ip_block_duration_seconds'] ?> seconds</dd></div>
      </dl>
    </section>
    <section class="content-panel admin-settings-panel">
      <h2>Change password</h2>
      <?php if ($error): ?><p class="alert-error" role="alert"><?= htmlspecialchars($error) ?></p><?php endif; ?>
      <?php include __DIR__ . '/../includes/password_change_form.php'; ?>
    </section>
    <section class="content-panel admin-settings-panel">
      <h2>Display</h2>
      <label class="admin-density-option" for="admin-compact-events">
        <input id="admin-compact-events" type="checkbox"> Compact event rows
      </label>
      <p>Saved in this browser.</p>
      <p id="admin-settings-status" role="status"></p>
    </section>
  </div>
</main>
<?php include __DIR__ . '/../includes/footer.php'; ?>
