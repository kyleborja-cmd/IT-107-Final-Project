<?php
require __DIR__ . '/../includes/session_security.php';
require_role('staff');
require __DIR__ . '/../includes/profile_validation.php';

$pdo = $GLOBALS['pdo'];
$userId = (int)$_SESSION['user']['id'];
$csrf = auth_csrf_token('staff_orders_csrf');
$transitions = [
    'Pending' => ['Processing', 'Cancelled'],
    'Processing' => ['Completed', 'Cancelled'],
];
$error = '';
$notice = $_SESSION['staff_order_notice'] ?? '';
unset($_SESSION['staff_order_notice']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!auth_valid_csrf('staff_orders_csrf', registration_raw_input('csrf_token'))) {
        auth_log_event($pdo, 'CSRF_REJECTED', $_SESSION['user']['username'] ?? null, $userId, 'purpose=staff_orders');
        http_response_code(403);
        $error = 'Reload the page and try again.';
    } elseif (registration_input('action') === 'update') {
        $orderId = filter_var(registration_input('order_id'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $current = registration_input('current_status');
        $next = registration_input('status');
        if (!$orderId || !in_array($next, $transitions[$current] ?? [], true)) {
            $error = 'Choose a valid status update.';
        } else {
            $stmt = $pdo->prepare('UPDATE orders SET status = ? WHERE id = ? AND assigned_to = ? AND status = ?');
            $stmt->execute([$next, $orderId, $userId, $current]);
            if ($stmt->rowCount()) {
                $_SESSION['staff_order_notice'] = 'Order status updated.';
                header('Location: orders.php', true, 303);
                exit;
            }
            $error = 'The order is unavailable or its status has changed. Reload and try again.';
        }
    } elseif (registration_input('action') === 'create') {
        $customerChoice = registration_input('customer_id');
        $name = registration_input('customer_name');
        $phone = registration_input('phone');
        $address = registration_input('delivery_address');
        $product = registration_input('product');
        $quantity = filter_var(registration_input('quantity'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 9999]]);
        $customerId = $customerChoice === 'new' ? null : filter_var($customerChoice, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if ($product === '' || registration_length($product) > 120 || !$quantity) {
            $error = 'Enter a product name up to 120 characters and a quantity from 1 to 9999.';
        } elseif ($customerId === false || ($customerId === null && ($name === '' || registration_length($name) > 120 || registration_length($phone) > 30 || registration_length($address) > 500))) {
            $error = 'Choose a customer or enter a name up to 120 characters, a phone up to 30, and an address up to 500.';
        } else {
            $code = 'WG-' . strtoupper(bin2hex(random_bytes(8)));
            if ($customerId === null) {
                $pdo->beginTransaction();
                try {
                    $stmt = $pdo->prepare('INSERT INTO customers (full_name, phone, address) VALUES (?, ?, ?)');
                    $stmt->execute([$name, $phone !== '' ? $phone : null, $address !== '' ? $address : null]);
                    $stmt = $pdo->prepare('INSERT INTO orders (order_code, customer_id, product_name, quantity, assigned_to)
                        VALUES (?, ?, ?, ?, ?)');
                    $stmt->execute([$code, (int)$pdo->lastInsertId(), $product, $quantity, $userId]);
                    $pdo->commit();
                } catch (Throwable $e) {
                    $pdo->rollBack();
                    throw $e;
                }
            } else {
                $stmt = $pdo->prepare('INSERT INTO orders (order_code, customer_id, product_name, quantity, assigned_to)
                    SELECT ?, c.id, ?, ?, ? FROM customers c WHERE c.id = ?
                    AND EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id AND o.assigned_to = ?)');
                $stmt->execute([$code, $product, $quantity, $userId, $customerId, $userId]);
                if ($stmt->rowCount() === 0) {
                    $error = 'Choose a customer from your assigned orders.';
                }
            }
            if ($error === '') {
                unset($_SESSION['staff_orders_csrf']);
                $_SESSION['staff_order_notice'] = "Order $code created.";
                header('Location: orders.php', true, 303);
                exit;
            }
        }
    }
}

$stmt = $pdo->prepare('SELECT o.id, o.order_code, o.product_name, o.quantity, o.status, c.full_name
    FROM orders o LEFT JOIN customers c ON c.id = o.customer_id WHERE o.assigned_to = ?
    ORDER BY o.created_at DESC, o.id DESC');
$stmt->execute([$userId]);
$orders = $stmt->fetchAll();

$stmt = $pdo->prepare('SELECT c.id, c.full_name FROM customers c
    WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id AND o.assigned_to = ?)
    ORDER BY c.full_name, c.id');
$stmt->execute([$userId]);
$customers = $stmt->fetchAll();

$pageTitle = 'My orders';
include __DIR__ . '/../includes/header.php';
?>
<div class="app-layout staff-workspace">
  <?php include __DIR__ . '/../includes/staff_navigation.php'; ?>
  <main class="dashboard-main">
    <div class="dash-content">
      <header class="welcome-row"><div><h1>My orders</h1></div><a class="btn btn-primary" href="#new-order">New order</a></header>
      <?php if ($notice): ?><p class="alert-success" role="status"><?= htmlspecialchars($notice) ?></p><?php endif; ?>
      <?php if ($error): ?><p class="alert-error" role="alert"><?= htmlspecialchars($error) ?></p><?php endif; ?>
      <section class="content-panel">
        <div class="panel-heading"><h2>Assigned orders</h2></div>
        <div class="table-scroll" role="region" tabindex="0" aria-label="Assigned orders">
          <table>
            <thead><tr><th>Order</th><th>Customer</th><th>Product</th><th>Quantity</th><th>Status</th><th>Update status</th></tr></thead>
            <tbody>
              <?php foreach ($orders as $order): ?>
                <tr>
                  <td><?= htmlspecialchars($order['order_code']) ?></td>
                  <td><?= htmlspecialchars($order['full_name'] ?? 'No customer') ?></td>
                  <td><?= htmlspecialchars($order['product_name']) ?></td>
                  <td><?= (int)$order['quantity'] ?></td>
                  <td><span class="status status-<?= htmlspecialchars(strtolower($order['status'])) ?>"><?= htmlspecialchars($order['status']) ?></span></td>
                  <td>
                    <?php if (isset($transitions[$order['status']])): ?>
                      <form method="post" class="staff-order-update">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
                        <input type="hidden" name="order_id" value="<?= (int)$order['id'] ?>">
                        <input type="hidden" name="current_status" value="<?= htmlspecialchars($order['status']) ?>">
                        <select name="status" required aria-label="New status for <?= htmlspecialchars($order['order_code']) ?>">
                          <?php foreach ($transitions[$order['status']] as $status): ?>
                            <option value="<?= htmlspecialchars($status) ?>"><?= htmlspecialchars($status) ?></option>
                          <?php endforeach; ?>
                        </select>
                        <button class="btn btn-primary" type="submit" name="action" value="update">Save</button>
                      </form>
                    <?php else: ?><span>Closed</span><?php endif; ?>
                  </td>
                </tr>
              <?php endforeach; ?>
              <?php if (!$orders): ?><tr><td colspan="6" class="empty-state">No orders are assigned to you yet.</td></tr><?php endif; ?>
            </tbody>
          </table>
        </div>
      </section>
      <section class="content-panel staff-order-create" id="new-order">
        <div class="panel-heading"><h2>New order</h2></div>
        <form class="auth-form" method="post">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
          <label for="customer_id">Customer</label>
          <select name="customer_id" id="customer_id">
            <option value="new">New customer</option>
            <?php foreach ($customers as $customer): ?>
              <option value="<?= (int)$customer['id'] ?>"<?= registration_input('customer_id') === (string)$customer['id'] ? ' selected' : '' ?>><?= htmlspecialchars($customer['full_name']) ?></option>
            <?php endforeach; ?>
          </select>
          <fieldset class="staff-customer-fields">
            <legend>For a new customer</legend>
            <label for="customer_name">Full name</label>
            <input id="customer_name" name="customer_name" maxlength="120" value="<?= htmlspecialchars(registration_input('customer_name')) ?>">
            <label for="phone">Phone (optional)</label>
            <input id="phone" name="phone" type="tel" maxlength="30" value="<?= htmlspecialchars(registration_input('phone')) ?>">
            <label for="delivery_address">Delivery address (optional)</label>
            <input id="delivery_address" name="delivery_address" maxlength="500" value="<?= htmlspecialchars(registration_input('delivery_address')) ?>">
          </fieldset>
          <label for="product">Product</label>
          <input id="product" name="product" maxlength="120" required value="<?= htmlspecialchars(registration_input('product')) ?>">
          <label for="quantity">Quantity</label>
          <input id="quantity" name="quantity" type="number" min="1" max="9999" required value="<?= htmlspecialchars(registration_input('quantity') ?: '1') ?>">
          <button class="btn btn-primary" type="submit" name="action" value="create">Create order</button>
        </form>
      </section>
    </div>
  </main>
</div>
<?php include __DIR__ . '/../includes/footer.php'; ?>
