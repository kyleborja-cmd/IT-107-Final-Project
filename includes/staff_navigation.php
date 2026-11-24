<aside class="sidebar staff-navigation">
  <a class="brand side-brand" href="../index.php" data-dashboard-home><span class="brand-mark">W</span><span>water<span class="brand-light">go</span><small>STAFF WORKSPACE</small></span></a>
  <nav aria-label="Staff workspace">
    <?php foreach (['dashboard.php' => 'Overview', 'orders.php' => 'My orders', 'customers.php' => 'Customers', 'security.php' => 'Account Security'] as $file => $label): ?>
      <a class="side-link<?= $currentPage === $file ? ' selected' : '' ?>" href="<?= $file ?>"<?= $currentPage === $file ? ' aria-current="page"' : '' ?>><?= $label ?></a>
    <?php endforeach; ?>
  </nav>
  <div class="security-sign-out"><?php auth_logout_form('../logout.php', 'Sign out'); ?></div>
</aside>
