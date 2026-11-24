<?php
$pageTitle = 'Pure water, delivered simply';
$bodyClass = 'water-home';
$extraStyles = ['/assets/css/home.css?v=' . filemtime(__DIR__ . '/assets/css/home.css')];
include __DIR__ . '/includes/header.php';
?>
<main class="home-main">
  <section class="water-scene" aria-labelledby="home-title">
    <div class="water-scene-bubbles" aria-hidden="true">
      <span></span><span></span><span></span><span></span><span></span><span></span>
    </div>
    <div class="water-scene-copy">
      <h1 id="home-title">Good water.<br><span>Good days.</span></h1>
      <p>Keep your home or office stocked with refreshing drinking water.</p>
      <div class="water-scene-actions">
        <button type="button" class="btn water-options-trigger" id="water-options-trigger" aria-haspopup="dialog">Water Options <span aria-hidden="true">&rarr;</span></button>
        <?php if ($isLoggedIn && ($_SESSION['login_otp_verified'] ?? false) === true): ?>
          <a class="btn water-scene-dashboard" href="dashboard.php">Open Dashboard</a>
        <?php endif; ?>
      </div>
    </div>
  </section>
</main>
<dialog id="water-options-dialog" class="water-options-dialog" aria-labelledby="water-options-title">
  <header class="water-options-heading">
    <h2 id="water-options-title">Water Options</h2>
    <p>Available in five-gallon containers.</p>
  </header>
  <dl class="water-options-list">
    <div><dt>Purified water</dt><dd>Filtered drinking water for everyday use.</dd></div>
    <div><dt>Mineral water</dt><dd>Drinking water with mineral content.</dd></div>
    <div><dt>Alkaline water</dt><dd>Drinking water with a higher pH.</dd></div>
  </dl>
  <form method="dialog"><button type="submit" class="btn water-options-trigger" autofocus>Close</button></form>
</dialog>
<?php include __DIR__ . '/includes/footer.php'; ?>
