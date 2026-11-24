<?php
require __DIR__ . '/../includes/session_security.php';
require_role('staff');

$pdo = $GLOBALS['pdo'];
$user = $_SESSION['user'];
$uid = (int)$user['id'];
$stmt = $pdo->prepare('SELECT status, COUNT(*) AS total FROM orders WHERE assigned_to = ? GROUP BY status');
$stmt->execute([$uid]);
$counts = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
$summary = ['Assigned orders' => array_sum($counts), 'Pending' => $counts['Pending'] ?? 0, 'Completed' => $counts['Completed'] ?? 0];

$stmt = $pdo->prepare('SELECT o.order_code, o.product_name, o.quantity, o.status, o.created_at, c.full_name
    FROM orders o LEFT JOIN customers c ON c.id = o.customer_id WHERE o.assigned_to = ?
    ORDER BY o.created_at DESC, o.id DESC LIMIT 8');
$stmt->execute([$uid]);
$recent = $stmt->fetchAll();

$pageTitle = 'Staff dashboard';
include __DIR__ . '/../includes/header.php';
?>
<div class="app-layout staff-workspace neon-dashboard">
  <?php include __DIR__ . '/../includes/staff_navigation.php'; ?>
  <main class="dashboard-main">
    <header class="dash-topbar">
      <b>Staff workspace</b>
      <div class="top-user"><span class="avatar staff-avatar" aria-hidden="true">S</span><span><b><?= htmlspecialchars((string)$user['full_name']) ?></b><small>Staff member</small></span></div>
    </header>
    <div class="dash-content">
      <section class="dash-banner staff-banner staff-overview">
        <div>
          <h1>Delivery overview</h1>
          <p>See what is assigned to you and what still needs attention.</p>
        </div>
        <a class="btn btn-primary" href="orders.php#new-order">New order</a>
      </section>
      <section class="stat-grid three-stats staff-order-summary" aria-label="Order summary">
        <?php foreach ($summary as $label => $count): ?>
          <article class="stat-card"><span class="stat-top"><?= htmlspecialchars($label) ?></span><strong><?= (int)$count ?></strong></article>
        <?php endforeach; ?>
      </section>
      <section class="content-panel">
        <div class="panel-heading">
          <div><h2>My assigned orders</h2><p>Up to eight recent orders.</p></div>
          <a href="orders.php">Manage orders &rarr;</a>
        </div>
        <div class="table-scroll" tabindex="0" role="region" aria-label="Recent assigned orders">
          <table>
            <thead><tr><th scope="col">Order</th><th scope="col">Customer</th><th scope="col">Product</th><th scope="col">Qty</th><th scope="col">Status</th><th scope="col">Date</th></tr></thead>
            <tbody>
              <?php if (!$recent): ?><tr><td colspan="6" class="empty-state">No orders are assigned to you yet.</td></tr><?php endif; ?>
              <?php foreach ($recent as $order): ?>
                <tr>
                  <td class="order-id"><?= htmlspecialchars($order['order_code']) ?></td>
                  <td><?= htmlspecialchars($order['full_name'] ?? 'No customer') ?></td>
                  <td><?= htmlspecialchars($order['product_name']) ?></td>
                  <td><?= (int)$order['quantity'] ?></td>
                  <td><span class="status status-<?= htmlspecialchars(strtolower($order['status'])) ?>"><?= htmlspecialchars($order['status']) ?></span></td>
                  <td><?= htmlspecialchars(date('M j, Y', strtotime($order['created_at']))) ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </main>
</div>
<?php include __DIR__ . '/../includes/footer.php'; ?>
