<?php
require 'includes/session_security.php';
require 'config/database.php';
require 'includes/profile_validation.php';
require 'includes/recaptcha.php';

$settings = require 'config/security.php';
$questionLabels = $settings['security_questions'];
$usernamePattern = '/^[A-Za-z][A-Za-z0-9]{' . ((int)$settings['username_min_length'] - 1) . ',' . ((int)$settings['username_max_length'] - 1) . '}$/D';

if (!empty($_SESSION['user'])) { header('Location: dashboard.php'); exit; }
if (empty($_SESSION['register_csrf'])) {
    $_SESSION['register_csrf'] = bin2hex(random_bytes(32));
}
if (isset($_GET['restart'])) {
    unset($_SESSION['pending_registration']);
    header('Location: register.php');
    exit;
}

if (($_POST['action'] ?? '') === 'check_username') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    $csrfToken = registration_input('csrf_token');
    $username = registration_input('username');
    if (!hash_equals($_SESSION['register_csrf'], $csrfToken)) {
        auth_log_event($pdo, 'CSRF_REJECTED', registration_input('username'), null, 'purpose=registration_username_check');
        http_response_code(400);
        echo json_encode(['available' => false, 'message' => 'Your session expired. Reload the page and try again.']);
        exit;
    }
    if (!preg_match($usernamePattern, $username)) {
        echo json_encode(['available' => false, 'message' => 'Username must start with a letter and use ' . $settings['username_min_length'] . '–' . $settings['username_max_length'] . ' letters or numbers.']);
        exit;
    }
    $stmt = $pdo->prepare('SELECT 1 FROM staff_registration_profiles WHERE username = ?
        UNION ALL SELECT 1 FROM users WHERE admin_username = ? LIMIT 1');
    $stmt->execute([$username, $username]);
    $available = !$stmt->fetch();
    echo json_encode([
        'available' => $available,
        'message' => $available ? 'Username is available.' : 'This username is already registered.',
    ]);
    exit;
}

$error = '';
$errorField = '';
$otpSent = false;
$pendingRegistration = $_SESSION['pending_registration'] ?? null;
if ($pendingRegistration && !isset($pendingRegistration['id'])) {
    unset($_SESSION['pending_registration']);
    $pendingRegistration = null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && in_array($_POST['action'] ?? '', ['verify', 'resend'], true)) {
    $action = $_POST['action'];
    if (!auth_valid_csrf('register_csrf', registration_input('csrf_token'))) {
        auth_log_event($pdo, 'CSRF_REJECTED', null, null, 'purpose=registration_otp');
        $error = 'Your session expired. Reload the page and try again.';
    } elseif (!$pendingRegistration && !$errorField) {
        $error = 'Start registration again to request a code.';
    } elseif ($action === 'resend') {
        $issued = auth_issue_otp($pdo, 'register', $pendingRegistration, $pendingRegistration['typed'], true);
        $error = $issued['error'] ?? '';
        if (!$error) {
            $pendingRegistration['otp_id'] = $issued['id'];
            $pendingRegistration['resend_at'] = $issued['resend_at'];
            $pendingRegistration['expires_at'] = $issued['expires_at'];
            $_SESSION['pending_registration'] = $pendingRegistration;
            $otpSent = true;
        }
    } elseif (auth_verify_otp($pdo, 'register', $pendingRegistration, registration_input('otp'))) {
        unset($_SESSION['pending_registration']);
        session_regenerate_id(true);
        $_SESSION['auth_notice'] = 'Your account is verified. Sign in to continue.';
        header('Location: login.php');
        exit;
    } else {
        $error = 'The OTP is invalid, expired, or has already been used.';
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (registration_raw_input('company_website') !== '') {
        header('Location: register.php', true, 303);
        exit;
    }
    $csrfToken = registration_input('csrf_token');
    if (!hash_equals($_SESSION['register_csrf'], $csrfToken)) {
        auth_log_event($pdo, 'CSRF_REJECTED', registration_input('username'), null, 'purpose=registration');
        $error = 'Your session expired. Reload the page and try again.';
    }
    $idNumber = registration_input('id_number');
    $username = registration_input('username');
    $firstName = registration_input('first_name');
    $middleName = registration_input('middle_name');
    $familyName = registration_input('family_name');
    $extensionChoice = registration_input('name_extension');
    $extensionOther = registration_input('name_extension_other');
    $email = strtolower(registration_raw_input('email'));
    $phone = registration_input('emergency_contact');
    $birthdate = registration_input('birthdate');
    $street = registration_input('purok_street');
    $barangay = registration_input('barangay');
    $city = registration_input('municipality_city');
    $province = registration_input('province');
    $country = registration_input('country');
    $zipCode = registration_input('zip_code');
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $confirmPassword = is_string($_POST['confirm_password'] ?? null) ? $_POST['confirm_password'] : '';
    $consent = registration_input('privacy_consent');
    $questions = [
        registration_input('security_question_1'),
        registration_input('security_question_2'),
        registration_input('security_question_3'),
    ];
    $answers = [
        registration_input('security_answer_1'),
        registration_input('security_answer_2'),
        registration_input('security_answer_3'),
    ];

    if ($error === '') {
        if ($idNumber === '') {
            $error = 'ID Number is required.';
        } elseif (!preg_match('/^\d{4}-\d{4}$/D', $idNumber)) {
            $error = 'ID Number must follow the format xxxx-xxxx.';
        } elseif ($username === '') {
            $error = 'Username is required.';
        } elseif (registration_length($username) < $settings['username_min_length'] || registration_length($username) > $settings['username_max_length'] || !preg_match('/^[A-Za-z][A-Za-z0-9]*$/D', $username)) {
            $error = 'Username must start with a letter and use ' . $settings['username_min_length'] . '–' . $settings['username_max_length'] . ' letters or numbers.';
        } elseif (($error = registration_name_error($firstName, 'First Name', true, (int)$settings['name_max_length'])) !== null) {
            $errorField = 'first_name';
        } elseif (($error = registration_name_error($middleName, 'Middle Name', false, (int)$settings['name_max_length'])) !== null) {
            $errorField = 'middle_name';
        } elseif (($error = registration_name_error($familyName, 'Last Name', true, (int)$settings['name_max_length'])) !== null) {
            $errorField = 'family_name';
        } elseif ($extensionChoice !== '' && !in_array($extensionChoice, ['Jr.', 'Sr.', 'Other'], true)) {
            $error = 'Choose Jr., Sr., or Other for Name Extension.';
        } elseif ($extensionChoice === 'Other' && !in_array($extensionOther, ['I', 'II', 'III', 'IV', 'IX', 'X'], true)) {
            $error = 'Name Extension must be I, II, III, IV, IX, or X.';
        } elseif ($email === '') {
            $error = 'Email is required.';
        } elseif (preg_match('/\s/', $email)) {
            $error = 'Email must not contain spaces.';
        } elseif (strlen($email) > 100) {
            $error = 'Email must be 100 characters or fewer.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please enter a valid email address.';
        } elseif (!preg_match('/^09\d{9}$/D', $phone)) {
            $error = 'Contact number must be 11 digits and start with 09.';
        } elseif ($birthdate === '') {
            $error = 'Birthdate is required.';
        } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/D', $birthdate) ||
            !DateTimeImmutable::createFromFormat('!Y-m-d', $birthdate) ||
            DateTimeImmutable::createFromFormat('!Y-m-d', $birthdate)->format('Y-m-d') !== $birthdate) {
            $error = 'Enter a valid birthdate.';
        } elseif ($birthdate > date('Y-m-d')) {
            $error = 'Birthdate cannot be in the future.';
        } elseif (($age = registration_age($birthdate)) === null) {
            $error = 'Enter a valid birthdate.';
        } elseif ($age < 18) {
            $error = 'You must be at least 18 years old to register.';
        } elseif (($error = registration_street_error($street)) !== null) {
        } elseif (($error = registration_address_name_error($barangay, 'Barangay')) !== null) {
        } elseif (($error = registration_address_name_error($city, 'Municipality / City')) !== null) {
        } elseif (($error = registration_address_name_error($province, 'Province')) !== null) {
        } elseif (($error = registration_address_name_error($country, 'Country', 100)) !== null) {
        } elseif (!preg_match('/^\d{4}$/D', $zipCode)) {
            $error = 'ZIP Code must be exactly 4 digits.';
        } elseif ($password === '') {
            $error = 'Password is required.';
        } elseif (registration_length($password) < $settings['password_min_length']) {
            $error = 'Password must be at least ' . $settings['password_min_length'] . ' characters.';
        } elseif (registration_length($password) > $settings['password_max_length']) {
            $error = 'Password must be ' . $settings['password_max_length'] . ' characters or fewer.';
        } elseif (registration_password_strength($password) === 'Weak') {
            $error = 'Password is weak. Use at least 8 characters and mix at least two character types.';
        } elseif ($password !== $confirmPassword) {
            $error = 'Passwords do not match.';
        } elseif (count(array_unique($questions)) !== 3 || count(array_filter($questions, static function ($question) use ($questionLabels) {
            return !array_key_exists($question, $questionLabels);
        })) > 0) {
            $error = 'Choose three different security questions from the list.';
        } elseif (($error = registration_security_answer_error($answers[0], 'Security answer 1')) !== null) {
        } elseif (($error = registration_security_answer_error($answers[1], 'Security answer 2')) !== null) {
        } elseif (($error = registration_security_answer_error($answers[2], 'Security answer 3')) !== null) {
        } elseif ($consent !== '1') {
            $error = 'You must agree to the Privacy Notice to register.';
        }
    }
    if ($error === null) {
        $error = '';
    }

    if ($error === '') {
        $fullName = implode(' ', array_filter([
            $firstName,
            $middleName,
            $familyName,
            $extensionChoice === 'Other' ? $extensionOther : $extensionChoice,
        ], static function ($part) { return $part !== ''; }));
        if (registration_length($fullName) > 500) {
            $error = 'Your combined name must be 500 characters or fewer.';
        }
    }

    if ($error === '') {
        $captchaStatus = recaptcha_verify_submission(
            is_string($_POST['g-recaptcha-response'] ?? null) ? $_POST['g-recaptcha-response'] : ''
        );
        if ($captchaStatus !== 'verified') {
            auth_log_event($pdo, 'CAPTCHA_FAILED', registration_input('username'), null, 'purpose=registration; status=' . $captchaStatus);
            $error = $captchaStatus === 'unavailable'
                ? 'Account creation verification is unavailable. Contact the administrator.'
                : 'Complete the reCAPTCHA check and try again.';
        }
    }

    if ($error === '') {
        $stmt = $pdo->prepare('SELECT u.id, u.password FROM users u JOIN staff_registration_profiles p ON p.user_id = u.id
            WHERE u.email = ? AND p.username = ? AND p.id_number = ? AND u.email_verified = 0');
        $stmt->execute([$email, $username, $idNumber]);
        $existing = $stmt->fetch();
        $userId = $existing && password_verify($password, $existing['password']) ? (int)$existing['id'] : 0;
        if (!$userId) {
            foreach ([
                ['SELECT 1 FROM staff_registration_profiles WHERE id_number = ?', $idNumber, 'This ID Number is already registered.'],
                ['SELECT 1 FROM staff_registration_profiles WHERE username = ?', $username, 'This username is already registered.'],
                ['SELECT 1 FROM users WHERE admin_username = ?', $username, 'This username is already registered.'],
                ['SELECT 1 FROM users WHERE email = ?', $email, 'This email is already registered.'],
            ] as [$query, $value, $message]) {
                $stmt = $pdo->prepare($query);
                $stmt->execute([$value]);
                if ($stmt->fetchColumn()) {
                    $error = $message;
                    break;
                }
            }
        }
    }
    if ($error === '') {
        try {
            if (!$userId) {
                $pdo->beginTransaction();
                $stmt = $pdo->prepare('INSERT INTO users (full_name, email, password, role, email_verified) VALUES (?, ?, ?, ?, 0)');
                $stmt->execute([$fullName, $email, password_hash($password, PASSWORD_ARGON2ID), 'staff']);
                $userId = (int)$pdo->lastInsertId();
                $stmt = $pdo->prepare('INSERT INTO staff_registration_profiles
                    (id_number, user_id, username, first_name, middle_name, family_name, name_extension,
                     emergency_contact, birthdate, purok_street, barangay, municipality_city, province,
                     country, zip_code, security_question_1, security_answer_1_hash, security_question_2,
                     security_answer_2_hash, security_question_3, security_answer_3_hash, privacy_consent_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
                $stmt->execute([
                    $idNumber, $userId, $username, $firstName, $middleName ?: null, $familyName,
                    $extensionChoice === 'Other' ? $extensionOther : ($extensionChoice ?: null),
                    registration_encrypt_contact($phone), $birthdate, $street, $barangay, $city, $province,
                    $country, $zipCode, $questions[0], password_hash(mb_strtolower($answers[0], 'UTF-8'), PASSWORD_DEFAULT),
                    $questions[1], password_hash(mb_strtolower($answers[1], 'UTF-8'), PASSWORD_DEFAULT),
                    $questions[2], password_hash(mb_strtolower($answers[2], 'UTF-8'), PASSWORD_DEFAULT), gmdate('Y-m-d H:i:s'),
                ]);
                auth_log_event($pdo, 'REGISTERED', $username, $userId, 'role=staff');
                $pdo->commit();
            }
            $pendingRegistration = ['id' => $userId, 'email' => $email, 'typed' => $username, 'otp_id' => 0, 'resend_at' => 0];
            $issued = auth_issue_otp($pdo, 'register', $pendingRegistration, $username);
            $error = $issued['error'] ?? '';
            if (!$error) {
                $pendingRegistration['otp_id'] = $issued['id'];
                $pendingRegistration['resend_at'] = $issued['resend_at'];
                $pendingRegistration['expires_at'] = $issued['expires_at'];
                $otpSent = true;
            }
            $_SESSION['pending_registration'] = $pendingRegistration;
        } catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($e->getCode() !== '23000') {
                throw $e;
            }
            $constraint = strtolower($e->errorInfo[2] ?? '');
            $error = match (true) {
                str_contains($constraint, 'primary') => 'This ID Number is already registered.',
                str_contains($constraint, 'username') => 'This username is already registered.',
                str_contains($constraint, 'email') => 'This email is already registered.',
                default => 'The account could not be saved. Try again.',
            };
        }
    }
}

$fieldMessages = [
    'ID Number' => 'id_number', 'Username' => 'username', 'This username' => 'username',
    'First Name' => 'first_name', 'Middle Name' => 'middle_name', 'Last Name' => 'family_name',
    'Name Extension' => 'name_extension', 'Email' => 'email', 'email address' => 'email',
    'This email' => 'email', 'Contact number' => 'emergency_contact',
    'Birthdate' => 'birthdate', 'birthdate' => 'birthdate', '18 years old' => 'birthdate',
    'Purok / Street' => 'purok_street', 'Barangay' => 'barangay', 'Municipality / City' => 'municipality_city',
    'Province' => 'province', 'Country' => 'country', 'ZIP Code' => 'zip_code',
    'Passwords do not match' => 'confirm_password', 'Password' => 'password',
    'three different security questions' => 'security_question_1',
    'Security answer 1' => 'security_answer_1', 'Security answer 2' => 'security_answer_2',
    'Security answer 3' => 'security_answer_3', 'Privacy Notice' => 'privacy_consent',
];
if (!$pendingRegistration && !$errorField) {
    foreach ($fieldMessages as $phrase => $field) {
        if (str_contains($error, $phrase)) {
            $errorField = $field;
            break;
        }
    }
}
function registration_field_error(string $field): void {
    global $error, $errorField;
    echo '<small class="field-error" data-field-error="' . registration_escape($field) . '" aria-live="polite">';
    if ($field === $errorField) {
        echo registration_escape($error);
    }
    echo '</small>';
}
$pageTitle = 'Create Account';
include 'includes/header.php';
function registration_escape(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>
<div class="login-page">
  <a class="login-back" href="index.php">← Back to home</a>
  <div class="login-shell register-shell">
    <div class="login-art">
      <a class="brand brand-on-dark" href="index.php"><span class="brand-mark">W</span><span>water<span class="brand-light">go</span><small>PURE WATER. EASY LIVING.</small></span></a>
    </div>
    <div class="login-form-wrap">
      <div class="login-form-inner register-form-inner">
        <?php if ($error && !$errorField): ?><div class="alert-error" role="alert"><?= registration_escape($error) ?></div><?php endif; ?>
        <?php if (is_array($pendingRegistration)): ?>
          <h2>Verify your email</h2>
          <p class="muted">Enter the six-digit verification code from your email.</p>
          <?php if ($otpSent): ?><div class="alert-success" role="status">A verification code has been sent to your email.</div><?php endif; ?>
          <form method="POST" class="auth-form">
            <input type="hidden" name="csrf_token" value="<?= registration_escape($_SESSION['register_csrf']) ?>">
            <?php auth_otp_input($pendingRegistration); ?>
          </form>
          <p><a href="register.php?restart=1">Start registration again</a></p>
        <?php else: ?>
        <h2>Create Account</h2>
        <form method="POST" class="auth-form register-form" id="register-form" data-username-min="<?= (int)$settings['username_min_length'] ?>" data-username-max="<?= (int)$settings['username_max_length'] ?>" data-password-min="<?= (int)$settings['password_min_length'] ?>" data-password-max="<?= (int)$settings['password_max_length'] ?>" data-name-max="<?= (int)$settings['name_max_length'] ?>" novalidate>
          <input type="hidden" name="csrf_token" value="<?= registration_escape($_SESSION['register_csrf']) ?>">
          <input type="hidden" name="action" value="register">
          <div hidden aria-hidden="true"><label for="company_website">Company website</label><input id="company_website" name="company_website" tabindex="-1" autocomplete="off"></div>
          <div class="register-fields">
            <div class="register-field"><label for="id_number">ID Number <span class="required-mark">*</span></label><input id="id_number" name="id_number" placeholder="xxxx-xxxx" required maxlength="9" value="<?= registration_escape(registration_input('id_number')) ?>"><?php registration_field_error('id_number'); ?></div>
            <div class="register-field"><label for="username">Username <span class="required-mark">*</span></label><input id="username" name="username" placeholder="<?= (int)$settings['username_min_length'] ?>–<?= (int)$settings['username_max_length'] ?> letters and numbers" required minlength="<?= (int)$settings['username_min_length'] ?>" maxlength="<?= (int)$settings['username_max_length'] ?>" autocomplete="username" value="<?= registration_escape(registration_input('username')) ?>"><small id="username-status" class="field-status" aria-live="polite"></small><?php registration_field_error('username'); ?></div>
            <div class="register-field"><label for="first_name">First Name <span class="required-mark">*</span></label><input id="first_name" name="first_name" required maxlength="<?= (int)$settings['name_max_length'] ?>" autocomplete="given-name" value="<?= registration_escape(registration_input('first_name')) ?>"><?php registration_field_error('first_name'); ?></div>
            <div class="register-field"><label for="middle_name">Middle Name <span>(optional)</span></label><input id="middle_name" name="middle_name" maxlength="<?= (int)$settings['name_max_length'] ?>" value="<?= registration_escape(registration_input('middle_name')) ?>"><?php registration_field_error('middle_name'); ?></div>
            <div class="register-field"><label for="family_name">Last Name <span class="required-mark">*</span></label><input id="family_name" name="family_name" required maxlength="<?= (int)$settings['name_max_length'] ?>" autocomplete="family-name" value="<?= registration_escape(registration_input('family_name')) ?>"><?php registration_field_error('family_name'); ?></div>
            <div class="register-field"><label for="name_extension">Name Extension <span>(optional)</span></label><select id="name_extension" name="name_extension"><option value="">None</option><option value="Jr."<?= registration_input('name_extension') === 'Jr.' ? ' selected' : '' ?>>Jr.</option><option value="Sr."<?= registration_input('name_extension') === 'Sr.' ? ' selected' : '' ?>>Sr.</option><option value="Other"<?= registration_input('name_extension') === 'Other' ? ' selected' : '' ?>>Other</option></select><input id="name_extension_other" name="name_extension_other" placeholder="I, II, III, IV, IX, or X" aria-label="Other name extension" maxlength="<?= (int)$settings['name_max_length'] ?>" value="<?= registration_escape(registration_input('name_extension_other')) ?>"><?php registration_field_error('name_extension'); ?></div>
            <div class="register-field"><label for="emergency_contact">Emergency Contact Number <span class="required-mark">*</span></label><input id="emergency_contact" name="emergency_contact" type="tel" required maxlength="11" autocomplete="tel" value="<?= registration_escape(registration_input('emergency_contact')) ?>"><?php registration_field_error('emergency_contact'); ?></div>
            <div class="register-field"><label for="email">Email <span class="required-mark">*</span></label><input id="email" name="email" type="email" required maxlength="100" autocomplete="email" value="<?= registration_escape(registration_input('email')) ?>"><?php registration_field_error('email'); ?></div>
            <div class="register-field"><label for="birthdate">Birthdate <span class="required-mark">*</span></label><input id="birthdate" name="birthdate" type="date" required max="<?= date('Y-m-d') ?>" value="<?= registration_escape(registration_input('birthdate')) ?>"><?php registration_field_error('birthdate'); ?></div>
            <div class="register-field"><label for="age-display">Age</label><input id="age-display" type="number" readonly aria-readonly="true"></div>
            <div class="register-field"><label for="purok_street">Purok / Street <span class="required-mark">*</span></label><input id="purok_street" name="purok_street" required minlength="2" maxlength="50" value="<?= registration_escape(registration_input('purok_street')) ?>"><?php registration_field_error('purok_street'); ?></div>
            <div class="register-field"><label for="barangay">Barangay <span class="required-mark">*</span></label><input id="barangay" name="barangay" required minlength="2" maxlength="50" value="<?= registration_escape(registration_input('barangay')) ?>"><?php registration_field_error('barangay'); ?></div>
            <div class="register-field"><label for="municipality_city">Municipality / City <span class="required-mark">*</span></label><input id="municipality_city" name="municipality_city" required minlength="2" maxlength="50" value="<?= registration_escape(registration_input('municipality_city')) ?>"><?php registration_field_error('municipality_city'); ?></div>
            <div class="register-field"><label for="province">Province <span class="required-mark">*</span></label><input id="province" name="province" required minlength="2" maxlength="50" value="<?= registration_escape(registration_input('province')) ?>"><?php registration_field_error('province'); ?></div>
            <div class="register-field"><label for="country">Country <span class="required-mark">*</span></label><input id="country" name="country" required maxlength="100" value="<?= registration_escape(registration_input('country') ?: 'Philippines') ?>"><?php registration_field_error('country'); ?></div>
            <div class="register-field"><label for="zip_code">ZIP Code <span class="required-mark">*</span></label><input id="zip_code" name="zip_code" inputmode="numeric" placeholder="4 digits" required maxlength="4" value="<?= registration_escape(registration_input('zip_code')) ?>"><?php registration_field_error('zip_code'); ?></div>
            <div class="register-password-pair">
              <div class="register-field register-password"><label for="password">Password <span class="required-mark">*</span></label><input id="password" name="password" type="password" placeholder="<?= (int)$settings['password_min_length'] ?>–<?= (int)$settings['password_max_length'] ?> characters" required minlength="<?= (int)$settings['password_min_length'] ?>" maxlength="<?= (int)$settings['password_max_length'] ?>" autocomplete="new-password"><meter id="password-meter" min="0" max="2" value="0" aria-label="Password strength meter"></meter><small id="password-strength" class="field-status" aria-live="polite">Password strength: Weak</small><?php registration_field_error('password'); ?></div>
              <div class="register-field register-confirm-password"><label for="confirm_password">Re-enter Password <span class="required-mark">*</span></label><input id="confirm_password" name="confirm_password" type="password" placeholder="Re-enter your password" required minlength="<?= (int)$settings['password_min_length'] ?>" maxlength="<?= (int)$settings['password_max_length'] ?>" autocomplete="new-password"><?php registration_field_error('confirm_password'); ?></div>
            </div>
            <?php for ($answerIndex = 1; $answerIndex <= 3; $answerIndex++): ?>
              <?php $selectedQuestion = registration_input('security_question_' . $answerIndex); ?>
              <div class="register-field"><label for="security_question_<?= $answerIndex ?>">Security Question <?= $answerIndex ?> <span class="required-mark">*</span></label><select id="security_question_<?= $answerIndex ?>" name="security_question_<?= $answerIndex ?>" required><option value="">Choose a question</option><?php foreach ($questionLabels as $questionId => $questionText): ?><option value="<?= registration_escape($questionId) ?>"<?= $selectedQuestion === $questionId ? ' selected' : '' ?>><?= registration_escape($questionText) ?></option><?php endforeach; ?></select><?php registration_field_error('security_question_' . $answerIndex); ?></div>
              <div class="register-field"><label for="security_answer_<?= $answerIndex ?>">Answer <?= $answerIndex ?> <span class="required-mark">*</span></label><input id="security_answer_<?= $answerIndex ?>" name="security_answer_<?= $answerIndex ?>" placeholder="Answer (2–50 letters and spaces)" required minlength="2" maxlength="50" value=""><?php registration_field_error('security_answer_' . $answerIndex); ?></div>
            <?php endfor; ?>
            <div class="register-field full privacy-consent"><label><input type="checkbox" name="privacy_consent" value="1" required<?= registration_input('privacy_consent') === '1' ? ' checked' : '' ?>> I have read the <a href="privacy.php" target="_blank" rel="noopener">Privacy Notice</a> and agree to the collection and processing of my personal data in accordance with the Data Privacy Act of 2012 (RA 10173).</label><?php registration_field_error('privacy_consent'); ?></div>
          </div>
          <?php recaptcha_render_widget(); ?>
          <button class="btn btn-primary submit-btn" type="submit">Create Account <span>→</span></button>
        </form>
        <?php endif; ?>
        <div class="login-note"><span>♢</span> Already have an account? <a href="login.php">Sign in</a></div>
      </div>
    </div>
  </div>
</div>
<?php include 'includes/footer.php'; ?>
