<?php
$pageTitle = 'Privacy Notice';
include 'includes/header.php';
?>
<main class="privacy-page">
  <a class="login-back" href="register.php">← Back to account creation</a>
  <article class="privacy-card">
    <div class="eyebrow">WATER GO / PRIVACY</div>
    <h1>Privacy Notice</h1>
    <p>Water Go collects personal information when you create a staff account. This notice explains what we collect and how we use it under the Data Privacy Act of 2012 (Republic Act No. 10173).</p>

    <h2>Information we collect and why</h2>
    <ul>
      <li><strong>First, middle, and last names and name extension:</strong> identify the staff account holder.</li>
      <li><strong>ID Number and username:</strong> identify the account and provide a unique sign-in name.</li>
      <li><strong>Email and emergency contact number:</strong> account communication and urgent staff contact. Water Go encrypts the emergency contact number.</li>
      <li><strong>Birthdate:</strong> verify the minimum registration age. Age is calculated for display and is not stored separately.</li>
      <li><strong>Street, barangay, city/municipality, province, country, and ZIP code:</strong> maintain the staff member's contact/address record.</li>
      <li><strong>Password:</strong> authenticate sign-in. Water Go stores a password hash, not the password itself.</li>
      <li><strong>Three security questions and answers:</strong> support account verification. Answers are normalized to lowercase and stored as password hashes; the selected questions are stored so the prompts can be identified.</li>
      <li><strong>Email verification:</strong> a six-digit code is sent to verify the email address before activating an account. A six-digit OTP is also required after the password for every sign-in. Pending registrations are stored as inactive accounts. OTP values are stored only as hashes and expire after five minutes.</li>
      <li><strong>Sign-in and recovery security records:</strong> a hashed version of the entered email/username, failed-attempt count, lockout tier, lockout expiry, and last-updated time support per-account sign-in cooldowns. Per-account lockout records are cleared after successful sign-in or password recovery. Ten failures from one IP within ten minutes trigger a 60-second block. Sign-in attempt counters and IP block records support that limit. Login and password-reset OTP hashes, expiry times, attempt counts, and request IP addresses are stored temporarily; OTP values are emailed and are never stored in plain text.</li>
      <li><strong>Security activity log:</strong> event type, the username/email entered, associated account ID when known, IP address, browser user agent, event details, and timestamp are kept for administrator security monitoring. Event records are append-only and do not contain passwords, OTP values, security answers, or session tokens.</li>
      <li><strong>Privacy consent date and time:</strong> record when you agreed to this notice.</li>
      <li><strong>Internal account ID, staff role, and account creation time:</strong> link your profile to its login account, apply staff access permissions, and record when the account was created.</li>
    </ul>

    <h2>Use and protection</h2>
    <p>Information is used to create and manage staff accounts, authenticate staff, support account verification and password recovery, prevent automated guessing, contact staff when necessary, and document consent. Access is limited to the Water Go system and its authorized administrators. Passwords, security answers, and stored OTPs are hashed; verification codes are sent to the email address provided. Database queries use parameterized statements. Do not reuse a password or security answer from another service.</p>

    <h2>Retention</h2>
    <p>Account information is retained while the staff account is active. After account closure, it is deleted or anonymized within one year unless a longer period is required to meet a legal obligation or resolve a dispute.</p>

    <h2>Your choices and contact</h2>
    <p>You may ask to access or correct your information, withdraw consent, or request deletion, subject to legal and operational requirements. Contact <a href="mailto:kyleborja2005@gmail.com">kyleborja2005@gmail.com</a> for privacy requests or questions.</p>
    <p class="privacy-law">Water Go handles personal information in accordance with the Data Privacy Act of 2012 (RA 10173).</p>
    <a class="btn btn-primary" href="register.php">Return to account creation <span>→</span></a>
  </article>
</main>
<?php include 'includes/footer.php'; ?>
