<?php
require_once __DIR__ . '/session_security.php';
$pageTitle = $pageTitle ?? 'Water Go';
// Resolve the project root so assets also load from /admin and /staff pages.
$scriptDir = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
$appBase = preg_replace('~/(admin|staff)(/.*)?$~', '', $scriptDir);
$appBase = rtrim($appBase, '/');
$currentPage = basename($_SERVER['SCRIPT_NAME'] ?? '');
$workspaceClass = preg_match('~/(admin|staff)$~', $scriptDir) ? ' water-workspace' : '';
$pageClasses = trim('water-theme' . $workspaceClass . ' ' . ($bodyClass ?? ''));
$isLoggedIn = !empty($_SESSION['user']);
$hasVerifiedSession = $isLoggedIn && ($_SESSION['login_otp_verified'] ?? false) === true;
$trackDashboardActivity = $hasVerifiedSession && $workspaceClass !== '';
$navigationItems = [
    ['label' => 'Home', 'url' => $appBase . '/index.php', 'active' => $currentPage === 'index.php'],
];
if ($isLoggedIn) {
    $navigationItems[] = ['label' => 'Log-out', 'url' => $appBase . '/logout.php', 'active' => false];
} else {
    if ($currentPage !== 'register.php') {
        $navigationItems[] = ['label' => 'Register', 'url' => $appBase . '/register.php', 'active' => false];
    }
    if ($currentPage !== 'login.php') {
        $navigationItems[] = ['label' => 'Log-in', 'url' => $appBase . '/login.php', 'active' => false];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?= htmlspecialchars($pageTitle) ?> | Water Go</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="<?= htmlspecialchars($appBase) ?>/assets/css/style.css?v=<?= filemtime(__DIR__ . '/../assets/css/style.css') ?>">
  <?php foreach (($extraStyles ?? []) as $style): ?>
  <link rel="stylesheet" href="<?= htmlspecialchars($appBase . '/' . ltrim((string)$style, '/'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
  <?php endforeach; ?>
  <link rel="stylesheet" href="<?= htmlspecialchars($appBase) ?>/assets/css/water-theme.css?v=<?= filemtime(__DIR__ . '/../assets/css/water-theme.css') ?>">
</head>
<body class="<?= htmlspecialchars($pageClasses, ENT_QUOTES, 'UTF-8') ?>"<?= $isLoggedIn ? ' data-idle-seconds="' . max(0, auth_settings()['idle_session_timeout_seconds'] - (time() - (int)($_SESSION['last_activity'] ?? 0))) . '"' : '' ?> data-login-url="<?= htmlspecialchars($appBase . '/login.php') ?>"
  <?php if ($hasVerifiedSession): ?>
  data-activity-url="<?= htmlspecialchars($appBase . '/session_activity.php', ENT_QUOTES, 'UTF-8') ?>" data-activity-token="<?= htmlspecialchars(auth_csrf_token('dashboard_activity_csrf'), ENT_QUOTES, 'UTF-8') ?>"
  <?php endif; ?><?= $trackDashboardActivity ? ' data-track-dashboard-activity' : '' ?>>
<div class="water-header">
<header class="site-header">
  <a class="brand" href="<?= htmlspecialchars($appBase . '/index.php', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>"<?= $trackDashboardActivity ? ' data-dashboard-home' : '' ?>><span class="brand-mark">W</span><span>water<span class="brand-light">go</span><small>PURE WATER. EASY LIVING.</small></span></a>
  <nav class="main-nav" aria-label="Primary navigation">
    <?php foreach ($navigationItems as $index => $item): ?>
      <?php if ($index > 0): ?><span class="nav-separator" aria-hidden="true">|</span><?php endif; ?>
      <?php if ($item['label'] === 'Log-out'): ?>
        <?php auth_logout_form($item['url'], 'Log-out'); ?>
      <?php else: ?>
      <a<?= $item['label'] === 'Register' && !empty($cooldownActive) ? ' data-register-link aria-disabled="true"' : ' href="' . htmlspecialchars($item['url'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"' ?><?= $item['active'] ? ' class="active"' : '' ?><?= $trackDashboardActivity && $item['label'] === 'Home' ? ' data-dashboard-home' : '' ?>><?= htmlspecialchars($item['label'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></a>
      <?php endif; ?>
    <?php endforeach; ?>
  </nav>
  <button class="menu-toggle" type="button" aria-label="Open navigation" aria-expanded="false">☰</button>
</header>
</div>
<?php if ($trackDashboardActivity): ?>
<dialog id="dashboard-home-dialog" class="dashboard-home-dialog" aria-labelledby="dashboard-home-title" aria-describedby="dashboard-home-description">
  <h2 id="dashboard-home-title">Go to Home?</h2>
  <p id="dashboard-home-description">Choose whether to stay signed in or log out.</p>
  <div class="dashboard-home-actions">
    <a class="btn" href="<?= htmlspecialchars($appBase . '/index.php', ENT_QUOTES, 'UTF-8') ?>">Stay signed in</a>
    <form method="post" action="<?= htmlspecialchars($appBase . '/logout.php', ENT_QUOTES, 'UTF-8') ?>">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(auth_csrf_token('logout_csrf'), ENT_QUOTES, 'UTF-8') ?>">
      <input type="hidden" name="destination" value="home">
      <button class="btn btn-primary" type="submit">Log out and go home</button>
    </form>
    <form method="dialog"><button class="btn dashboard-home-cancel">Cancel</button></form>
  </div>
</dialog>
<?php endif; ?>
<?php if ($hasVerifiedSession): ?>
<dialog id="sign-out-dialog" class="dashboard-home-dialog" aria-labelledby="sign-out-title" aria-describedby="sign-out-description">
  <h2 id="sign-out-title">Sign out of Water Go?</h2>
  <p id="sign-out-description">You’ll need to sign in again to return to your dashboard.</p>
  <div class="dashboard-home-actions">
    <form method="dialog"><button class="btn dashboard-home-cancel" type="submit" autofocus>Stay signed in</button></form>
    <form method="post" action="<?= htmlspecialchars($appBase . '/logout.php', ENT_QUOTES, 'UTF-8') ?>">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(auth_csrf_token('logout_csrf'), ENT_QUOTES, 'UTF-8') ?>">
      <button class="btn btn-primary" type="submit">Sign out</button>
    </form>
  </div>
</dialog>
<dialog id="session-warning-dialog" class="dashboard-home-dialog" aria-labelledby="session-warning-title" aria-describedby="session-warning-description">
  <h2 id="session-warning-title">Session expiring</h2>
  <p id="session-warning-description">Your session expires in <strong data-session-seconds>10</strong> seconds.</p>
  <div class="dashboard-home-actions">
    <button type="button" class="btn btn-primary" data-stay-signed-in>Stay signed in</button>
    <form method="post" action="<?= htmlspecialchars($appBase . '/logout.php', ENT_QUOTES, 'UTF-8') ?>">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(auth_csrf_token('logout_csrf'), ENT_QUOTES, 'UTF-8') ?>">
      <button class="btn dashboard-home-cancel" type="submit">Sign out</button>
    </form>
  </div>
</dialog>
<?php endif; ?>
