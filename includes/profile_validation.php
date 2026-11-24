<?php
function registration_input(string $name): string {
    return trim(registration_raw_input($name));
}

function registration_raw_input(string $name): string {
    return is_string($_POST[$name] ?? null) ? $_POST[$name] : '';
}

function registration_length(string $value): int {
    $length = preg_match_all('/./us', $value);
    return $length === false ? PHP_INT_MAX : $length;
}

function registration_name_error(string $value, string $label, bool $required = true, int $maximum = 50): ?string {
    if ($value === '') {
        return $required ? "$label is required." : null;
    }
    if (preg_match('/\p{N}/u', $value)) {
        return "Numbers are not allowed in $label.";
    }
    if (!preg_match('/^[\p{L} ]+$/u', $value)) {
        return "Special characters are not allowed in $label.";
    }
    if (str_contains($value, '  ')) {
        return 'Double space is not allowed.';
    }
    if (preg_match('/(.)\1{2}/iu', $value)) {
        return 'Three consecutive identical letters are not allowed.';
    }
    $length = registration_length($value);
    if ($length < 2 || $length > $maximum) {
        return "$label must be between 2 and $maximum characters.";
    }
    if (preg_match('/\p{Lu}/u', $value) && !preg_match('/\p{Ll}/u', $value)) {
        return 'Do not use all capital letters.';
    }
    if (!preg_match('/^\p{Lu}\p{Ll}*(?: \p{Lu}\p{Ll}*)*$/u', $value)) {
        return 'First letter of your name must be capital.';
    }
    return null;
}

function registration_address_name_error(string $value, string $label, int $maximum = 50): ?string {
    if ($value === '') {
        return "$label is required.";
    }
    if (preg_match('/\p{N}/u', $value)) {
        return "Numbers are not allowed in $label.";
    }
    if (!preg_match('/^[\p{L} ]+$/u', $value)) {
        return "Only letters and spaces are allowed in $label.";
    }
    if (str_contains($value, '  ')) {
        return "Double space is not allowed in $label.";
    }
    $length = registration_length($value);
    if ($length < 2 || $length > $maximum) {
        return "$label must be between 2 and $maximum characters.";
    }
    if (preg_match('/\p{Lu}/u', $value) && !preg_match('/\p{Ll}/u', $value)) {
        return "$label must not be all capital letters.";
    }
    if (!preg_match('/^\p{Lu}\p{Ll}*(?: \p{Lu}\p{Ll}*)*$/u', $value)) {
        return "First letter of each word in $label must be capital.";
    }
    return null;
}

function registration_street_error(string $value): ?string {
    if ($value === '') {
        return 'Purok / Street is required.';
    }
    if (str_contains($value, '  ')) {
        return 'Double space is not allowed in Purok / Street.';
    }
    if (!preg_match('/^[\p{L}\p{N}]+(?: [\p{L}\p{N}]+)*$/u', $value)) {
        return 'Purok / Street may contain only letters, numbers, and spaces.';
    }
    $length = registration_length($value);
    return $length < 2 || $length > 50 ? 'Purok / Street must be between 2 and 50 characters.' : null;
}

function registration_valid_date(string $value): bool {
    if (!preg_match('/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/D', $value)) {
        return false;
    }
    $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value);
    return $date && $date->format('Y-m-d') === $value;
}

function registration_age(string $birthdate): ?int {
    if (!registration_valid_date($birthdate)) {
        return null;
    }
    $date = new DateTimeImmutable($birthdate);
    $today = new DateTimeImmutable('today');
    return $date > $today ? null : $date->diff($today)->y;
}

function registration_password_strength(string $password): string {
    $length = registration_length($password);
    $types = (int)(bool)preg_match('/[a-z]/', $password)
        + (int)(bool)preg_match('/[A-Z]/', $password)
        + (int)(bool)preg_match('/[0-9]/', $password)
        + (int)(bool)preg_match('/[^a-zA-Z0-9]/', $password);
    if ($length < 8 || $types < 2) {
        return 'Weak';
    }
    return $length >= 12 && $types >= 3 ? 'Strong' : 'Medium';
}

function registration_security_answer_error(string $answer, string $label): ?string {
    if ($answer === '') {
        return "$label is required.";
    }
    if (str_contains($answer, '  ')) {
        return "Double space is not allowed in $label.";
    }
    if (!preg_match('/^\p{L}+(?: \p{L}+)*$/u', $answer)) {
        return "$label may contain only letters and spaces.";
    }
    $length = registration_length($answer);
    return $length < 2 || $length > 50 ? "$label must be between 2 and 50 characters." : null;
}

function registration_encryption_key(): string {
    $key = base64_decode($GLOBALS['waterGoPrivate']['encryption_key'] ?? '', true);
    if ($key === false || strlen($key) !== 32) {
        throw new RuntimeException('Configure the 32-byte Water Go encryption key.');
    }
    return $key;
}

function registration_encrypt_contact(string $phone): string {
    $iv = random_bytes(12);
    $ciphertext = openssl_encrypt($phone, 'aes-256-gcm', registration_encryption_key(), OPENSSL_RAW_DATA, $iv, $tag);
    if ($ciphertext === false) {
        throw new RuntimeException('Could not encrypt the emergency contact.');
    }
    return 'gcm1:' . base64_encode($iv . $tag . $ciphertext);
}

function registration_decrypt_contact(string $stored): string {
    if (!str_starts_with($stored, 'gcm1:')) {
        return $stored;
    }
    $data = base64_decode(substr($stored, 5), true);
    if ($data === false || strlen($data) <= 28) {
        throw new RuntimeException('Could not read the emergency contact.');
    }
    $phone = openssl_decrypt(substr($data, 28), 'aes-256-gcm', registration_encryption_key(),
        OPENSSL_RAW_DATA, substr($data, 0, 12), substr($data, 12, 16));
    if ($phone === false) {
        throw new RuntimeException('Could not authenticate the emergency contact.');
    }
    return $phone;
}

function registration_encrypt_existing_contacts(PDO $pdo): int {
    $pdo->beginTransaction();
    try {
        $read = $pdo->prepare("SELECT id_number, emergency_contact FROM staff_registration_profiles
                              WHERE emergency_contact NOT LIKE 'gcm1:%' FOR UPDATE");
        $read->execute();
        $rows = $read->fetchAll();
        $write = $pdo->prepare('UPDATE staff_registration_profiles SET emergency_contact = ? WHERE id_number = ?');
        foreach ($rows as $row) {
            $write->execute([registration_encrypt_contact($row['emergency_contact']), $row['id_number']]);
        }
        $pdo->commit();
        return count($rows);
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $error;
    }
}

function registration_recovery_answers(PDO $pdo, array $account): array {
    if ($account['role'] === 'admin') {
        $stmt = $pdo->prepare('SELECT question_id, answer_hash FROM admin_recovery_questions WHERE user_id = ? ORDER BY question_id');
        $stmt->execute([(int)$account['id']]);
        $answers = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
        if (count($answers) === 3) {
            return $answers;
        }
    }

    $stmt = $pdo->prepare('SELECT security_question_1, security_answer_1_hash, security_question_2, security_answer_2_hash,
        security_question_3, security_answer_3_hash FROM staff_registration_profiles WHERE user_id = ?');
    $stmt->execute([(int)$account['id']]);
    $profile = $stmt->fetch();
    if (!$profile) {
        return [];
    }
    return [
        $profile['security_question_1'] => $profile['security_answer_1_hash'],
        $profile['security_question_2'] => $profile['security_answer_2_hash'],
        $profile['security_question_3'] => $profile['security_answer_3_hash'],
    ];
}
