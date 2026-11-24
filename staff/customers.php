<?php
require __DIR__ . '/../includes/session_security.php';
require_role('staff');

$pdo = $GLOBALS['pdo'];
$stmt = $pdo->prepare('SELECT c.full_name, c.phone, c.address, COUNT(*) AS order_count
    FROM customers c JOIN orders o ON c.id = o.customer_id
    WHERE o.assigned_to = ? GROUP BY c.id, c.full_name, c.phone, c.address
    ORDER BY c.full_name, c.id');
$stmt->execute([(int)$_SESSION['user']['id']]);
$customers = $stmt->fetchAll();

$pageTitle = 'Customers';
include __DIR__ . '/../includes/header.php';
?>
<div class="app-layout staff-workspace">
  <?php include __DIR__ . '/../includes/staff_navigation.php'; ?>
  <main class="dashboard-main">
    <div class="dash-content">
      <header class="welcome-row"><div><h1>Customers</h1><p>Contact and delivery details for your assigned orders.</p></div><a class="btn btn-primary" href="orders.php#new-order">New order</a></header>
      <section class="content-panel">
        <div class="table-scroll" role="region" tabindex="0" aria-label="My customers">
          <table>
            <thead><tr><th>Customer</th><th>Phone</th><th>Delivery address</th><th>My orders</th></tr></thead>
            <tbody>
              <?php foreach ($customers as $customer): ?>
                <tr>
                  <td><?= htmlspecialchars($customer['full_name']) ?></td>
                  <td><?= htmlspecialchars($customer['phone'] ?: 'Not provided') ?></td>
                  <td><?= htmlspecialchars($customer['address'] ?: 'Not provided') ?></td>
                  <td><?= (int)$customer['order_count'] ?></td>
                </tr>
              <?php endforeach; ?>
              <?php if (!$customers): ?><tr><td colspan="4" class="empty-state">Customers appear here after an order is assigned to you.</td></tr><?php endif; ?>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </main>
</div>
<?php include __DIR__ . '/../includes/footer.php'; ?>
