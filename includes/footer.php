<footer class="site-footer copyright-footer">© <?= date('Y') ?> Water Go. All rights reserved.</footer>
<script src="<?= htmlspecialchars($appBase ?? '') ?>/assets/js/app.js?v=<?= filemtime(__DIR__ . '/../assets/js/app.js') ?>"></script>
<?php foreach (($extraScripts ?? []) as $script): ?>
<script src="<?= htmlspecialchars((string)$script, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>" defer></script>
<?php endforeach; ?>
</body>
</html>
