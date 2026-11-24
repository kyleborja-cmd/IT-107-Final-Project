<form method="post" class="auth-form" data-password-strength-form>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>">
        <label for="current_password">Current password</label>
        <input id="current_password" name="current_password" type="password" required autocomplete="current-password">
        <label for="password">New password</label>
        <input id="password" name="password" type="password" required minlength="<?= (int)$settings['password_min_length'] ?>" maxlength="<?= (int)$settings['password_max_length'] ?>" autocomplete="new-password">
        <meter id="password-meter" min="0" max="2" value="0" aria-label="Password strength"></meter>
        <p id="password-strength" class="field-status" aria-live="polite">Password strength: Weak</p>
        <label for="confirm_password">Re-enter new password</label>
        <input id="confirm_password" name="confirm_password" type="password" required minlength="<?= (int)$settings['password_min_length'] ?>" maxlength="<?= (int)$settings['password_max_length'] ?>" autocomplete="new-password">
        <button class="btn btn-primary" type="submit">Change password</button>
      </form>
