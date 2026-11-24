<?php
ini_set('display_errors', '0');
error_reporting(E_ALL);
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, private');

require '../includes/session_security.php';
require '../config/database.php';

$user = auth_current_user($pdo, false);
if (($user['role'] ?? null) !== 'admin') {
    auth_log_event(
        $pdo,
        'ADMIN_ACCESS_DENIED',
        $user ? (string)($user['username'] ?? $user['email'] ?? '') : null,
        $user ? (int)$user['id'] : null,
        'endpoint=dashboard'
    );
    http_response_code(403);
    $pageTitle = 'Access denied';
    $extraStyles = ['/assets/css/security-dashboard.css'];
    include __DIR__ . '/../includes/header.php';
    ?>
    <main class="access-denied">
      <h1>Access denied</h1>
      <p>This page is available to administrators who have verified their sign-in OTP.</p>
      <a href="../login.php">Return to sign in</a>
    </main>
    <?php
    include __DIR__ . '/../includes/footer.php';
    exit;
}

$_SESSION['last_activity'] = time();
auth_log_event($pdo, 'ADMIN_VIEWED_DASHBOARD', (string)($user['username'] ?? $user['email']), (int)$user['id'], 'dashboard_opened');
$pageTitle = 'Security Monitoring';
$extraStyles = ['/assets/css/security-dashboard.css?v=' . filemtime(__DIR__ . '/../assets/css/security-dashboard.css')];
$extraScripts = [
    '../assets/js/security-dashboard.js?v=' . filemtime(__DIR__ . '/../assets/js/security-dashboard.js'),
];
$initialFilters = [
    'date_from' => is_string($_GET['date_from'] ?? null) ? $_GET['date_from'] : '',
    'date_to' => is_string($_GET['date_to'] ?? null) ? $_GET['date_to'] : '',
    'event_type' => is_string($_GET['event_type'] ?? null) ? $_GET['event_type'] : '',
    'status' => is_string($_GET['status'] ?? null) ? $_GET['status'] : '',
    'username' => is_string($_GET['username'] ?? null) ? $_GET['username'] : '',
    'ip_address' => is_string($_GET['ip_address'] ?? null) ? $_GET['ip_address'] : '',
];
$statuses = require __DIR__ . '/../includes/security_statuses.php';
include '../includes/header.php';
?>
<div class="app-layout security-layout neon-dashboard">
  <aside class="sidebar security-sidebar">
    <a class="brand side-brand" href="../index.php" data-dashboard-home><span class="brand-mark">W</span><span>water<span class="brand-light">go</span><small>SECURITY CENTER</small></span></a>
    <nav class="security-section-nav" aria-label="Security dashboard sections">
      <a class="side-link selected" href="#security-overview">Overview</a>
      <a class="side-link" href="#login-monitoring">Sign-in activity</a>
      <a class="side-link" href="#ip-monitoring">IP addresses</a>
      <a class="side-link" href="#ip-blocks">IP blocks</a>
      <a class="side-link" href="#security-flags">Security flags</a>
      <a class="side-link" href="#activity-logs">Event log</a>
    </nav>
    <a class="side-link" href="settings.php">Settings</a>
    <div class="security-sign-out"><?php auth_logout_form('../logout.php', 'Sign out'); ?></div>
  </aside>
  <main class="dashboard-main security-dashboard" id="security-dashboard" data-endpoint="security_data.php">
    <header class="dash-topbar">
      <b>Administrator workspace</b>
      <div class="top-user"><span class="avatar" aria-hidden="true">A</span><span><b><?= htmlspecialchars((string)$user['full_name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></b><small>Administrator</small></span></div>
    </header>
    <div class="dash-content">
      <section id="security-overview" class="security-hero">
        <div><h1>Security monitoring</h1><p>Review sign-ins, account protections, and recent security events.</p></div>
        <div class="security-refresh">
          <p class="refresh-meta">Last updated <time id="last-refresh">Loading&hellip;</time></p>
          <button id="refresh-security" type="button" class="btn">Refresh</button>
        </div>
      </section>
      <div id="dashboard-error" class="alert-error security-error" role="alert" hidden></div>
      <section class="security-summary-grid" aria-label="Today's security summary">
        <article class="security-summary-card"><span>Successful sign-ins today</span><strong data-summary="successful_logins">—</strong></article>
        <article class="security-summary-card security-summary-attention"><span>Failed sign-ins today</span><strong data-summary="failed_logins">—</strong></article>
        <article class="security-summary-card security-summary-attention"><span>Locked accounts</span><strong data-summary="locked_accounts">—</strong></article>
        <article class="security-summary-card security-summary-attention"><span>Blocked IP addresses</span><strong data-summary="blocked_ips">—</strong></article>
        <article class="security-summary-card"><span>OTPs sent today</span><strong data-summary="otps_sent">—</strong></article>
        <article class="security-summary-card security-summary-attention"><span>Failed OTP attempts today</span><strong data-summary="failed_otp_attempts">—</strong></article>
        <article class="security-summary-card"><span>Alert emails sent today</span><strong data-summary="alert_emails_sent">—</strong></article>
      </section>
      <section id="login-monitoring" class="content-panel security-panel">
        <div class="panel-heading"><div><h2>Failed sign-ins</h2><p>Hourly totals over the last 24 hours (Philippine time).</p></div></div>
        <div class="security-chart-wrap">
          <p class="chart-reading" id="failed-login-reading" aria-live="polite">Select an hour to see the exact count.</p>
          <div class="chart-with-axis">
            <div class="chart-scale" id="failed-login-scale" aria-hidden="true"></div>
            <div class="chart-scroll" role="region" tabindex="0" aria-label="Scroll through hourly failed sign-ins">
              <div id="failed-login-chart" class="hourly-chart" role="group" aria-label="Hourly failed sign-ins"></div>
            </div>
          </div>
        </div>
      </section>
      <section id="ip-blocks" class="content-panel security-panel">
        <div class="panel-heading"><div><h2>IP blocks</h2><p>Active blocks and the latest block per IP in the last 24 hours.</p></div></div>
        <div class="table-scroll" tabindex="0" role="region" aria-label="IP blocks">
          <table>
            <thead><tr><th scope="col">IP address</th><th scope="col">Username entered</th><th scope="col">Status</th><th scope="col">Blocked at (PH)</th><th scope="col">Expires at (PH)</th></tr></thead>
            <tbody id="ip-block-rows"><tr><td colspan="5" class="empty-state">Loading IP blocks&hellip;</td></tr></tbody>
          </table>
        </div>
      </section>
      <section id="ip-monitoring" class="content-panel security-panel">
        <div class="panel-heading"><div><h2>Top five IP addresses by failed sign-ins</h2><p>Last 24 hours, with current block status.</p></div></div>
        <div class="table-scroll" tabindex="0" role="region" aria-label="IP activity"><table><thead><tr><th>IP ADDRESS</th><th>FAILED LOGINS</th><th>BLOCK STATUS</th><th>BLOCK EXPIRATION (PH TIME)</th></tr></thead><tbody id="top-ip-rows"><tr><td colspan="4" class="empty-state">Loading IP activity…</td></tr></tbody></table></div>
      </section>
      <section id="security-flags" class="content-panel security-panel">
        <div class="panel-heading"><div><h2>Security flags</h2><p>Findings from the security monitoring report.</p></div></div>
        <div class="table-scroll" tabindex="0" role="region" aria-label="Security flags"><table><thead><tr><th>FLAG TYPE</th><th>SEVERITY</th><th>AFFECTED USER / IP</th><th>DESCRIPTION</th><th>DETECTED (PH TIME)</th></tr></thead><tbody id="security-flag-rows"><tr><td colspan="5" class="empty-state">Loading security flags…</td></tr></tbody></table></div>
      </section>
      <section id="activity-logs" class="content-panel security-panel">
        <div class="panel-heading"><div><h2>Recent security events</h2><p>Up to 50 matching events, newest first.</p></div></div>
        <form id="security-filters" class="security-filters">
          <label>Date from<input type="date" name="date_from" value="<?= htmlspecialchars($initialFilters['date_from'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>"></label>
          <label>Date to<input type="date" name="date_to" value="<?= htmlspecialchars($initialFilters['date_to'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>"></label>
          <label>Event type<select name="event_type">
            <option value="">All event types</option>
            <?php foreach (array_merge(...array_values($statuses)) as $type): ?>
              <option value="<?= htmlspecialchars($type) ?>"<?= $initialFilters['event_type'] === $type ? ' selected' : '' ?>><?= htmlspecialchars(ucwords(strtolower(str_replace('_', ' ', $type)))) ?></option>
            <?php endforeach; ?>
          </select></label>
          <label>Status<select name="status">
            <option value="">All statuses</option>
            <?php foreach (array_keys($statuses) as $status): ?>
              <option value="<?= htmlspecialchars($status) ?>"<?= $initialFilters['status'] === $status ? ' selected' : '' ?>><?= htmlspecialchars($status) ?></option>
            <?php endforeach; ?>
          </select></label>
          <label>Username<input type="search" name="username" maxlength="200" value="<?= htmlspecialchars($initialFilters['username'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>" placeholder="Search username"></label>
          <label>IP address<input type="text" name="ip_address" maxlength="45" value="<?= htmlspecialchars($initialFilters['ip_address'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>" placeholder="IPv4 or IPv6"></label>
          <div class="security-filter-actions"><button class="btn btn-primary" type="submit">Apply filters</button><button class="btn btn-secondary" type="reset">Clear</button></div>
        </form>
        <div class="table-scroll" tabindex="0" role="region" aria-label="Recent security events"><table class="activity-table"><thead><tr><th>EVENT ID</th><th>DATE / TIME (PH)</th><th>STATUS</th><th>USERNAME TYPED</th><th>USER ID</th><th>IP ADDRESS</th><th>BROWSER / USER AGENT</th></tr></thead><tbody id="security-event-rows"><tr><td colspan="7" class="empty-state">Loading security events…</td></tr></tbody></table></div>
      </section>

    </div>
  </main>
</div>
<?php include '../includes/footer.php'; ?>
