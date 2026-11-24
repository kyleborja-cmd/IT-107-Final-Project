<?php
require __DIR__ . '/../includes/session_security.php';
require_role('staff');
require __DIR__ . '/../includes/profile_validation.php';
require __DIR__ . '/../includes/signed_in_password.php';

$pdo = $GLOBALS['pdo'];
$user = $_SESSION['user'];
$userId = (int)$user['id'];
$settings = auth_settings();
$csrf = auth_csrf_token('staff_password_csrf');
$error = auth_handle_signed_in_password_change($pdo, $user, 'staff_password_csrf');
$recoveryReady = count(registration_recovery_answers($pdo, $user)) === 3;

$stmt = $pdo->prepare('SELECT created_at FROM security_events
    WHERE user_id = ? AND event_type = ? ORDER BY created_at DESC, id DESC LIMIT 1');
$stmt->execute([$userId, 'LOGIN_SUCCESS']);
$lastLogin = $stmt->fetchColumn();
$lastLoginLabel = $lastLogin ? (new DateTimeImmutable($lastLogin, new DateTimeZone('UTC')))
    ->setTimezone(new DateTimeZone('Asia/Manila'))->format('M j, Y g:i A') : 'No sign-in recorded';

$stmt = $pdo->prepare('SELECT emergency_contact FROM staff_registration_profiles WHERE user_id = ?');
$stmt->execute([$userId]);
$storedContact = $stmt->fetchColumn();

$pageTitle = 'Account security';
include __DIR__ . '/../includes/header.php';
?>
<div class="app-layout staff-workspace">
  <?php include __DIR__ . '/../includes/staff_navigation.php'; ?>
  <main class="dashboard-main">
    <div class="dash-content">
      <header class="welcome-row"><div><h1>Account Security</h1><p>Review and protect your staff account.</p></div></header>
      <div class="admin-settings-grid">
        <section class="content-panel admin-settings-panel">
          <h2>Sign-in protection</h2>
          <dl>
            <div><dt>Email</dt><dd><?= htmlspecialchars((string)$user['email']) ?></dd></div>
            <div><dt>Email verification</dt><dd>Verified</dd></div>
            <div><dt>Verification method</dt><dd>Email code</dd></div>
            <div><dt>Last successful sign-in (PH)</dt><dd><?= htmlspecialchars($lastLoginLabel) ?></dd></div>
            <div><dt>Recovery questions</dt><dd><?= $recoveryReady ? 'Configured' : 'Not configured' ?></dd></div>
          </dl>
          <?php if ($storedContact !== false): ?>
            <details><summary>My emergency contact</summary><p><?= htmlspecialchars(registration_decrypt_contact($storedContact)) ?></p></details>
          <?php endif; ?>
        </section>
        <section class="content-panel admin-settings-panel">
          <h2>Change password</h2>
          <?php if ($error): ?><p class="alert-error" role="alert"><?= htmlspecialchars($error) ?></p><?php endif; ?>
          <?php include __DIR__ . '/../includes/password_change_form.php'; ?>
        </section>
      </div>
    </div>
  </main>
</div>
<?php include __DIR__ . '/../includes/footer.php'; ?>