<?php
function recaptcha_keys(): array {
    $siteKey = ($GLOBALS['waterGoPrivate']['recaptcha']['site_key'] ?? getenv('WATER_GO_RECAPTCHA_SITE_KEY'));
    $secretKey = ($GLOBALS['waterGoPrivate']['recaptcha']['secret_key'] ?? getenv('WATER_GO_RECAPTCHA_SECRET_KEY'));
    return [
        'site' => is_string($siteKey) ? trim($siteKey) : '',
        'secret' => is_string($secretKey) ? trim($secretKey) : '',
    ];
}

function recaptcha_render_widget(): void {
    $keys = recaptcha_keys();
    if ($keys['site'] === '') {
        echo '<p class="recaptcha-notice" role="alert">Verification is temporarily unavailable.</p>';
        return;
    }

    $siteKey = htmlspecialchars($keys['site'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    echo '<div class="recaptcha-widget"><div class="g-recaptcha" data-sitekey="' . $siteKey . '"></div></div>';
    echo '<script src="https://www.google.com/recaptcha/api.js" async defer></script>';
}

function recaptcha_verify_submission(string $response): string {
    $keys = recaptcha_keys();
    if ($keys['site'] === '' || $keys['secret'] === '' || !function_exists('curl_init')) {
        error_log('Water Go reCAPTCHA verification is unavailable. Configure both keys and enable PHP cURL.');
        return 'unavailable';
    }
    if ($response === '') {
        return 'invalid';
    }

    $curl = curl_init('https://www.google.com/recaptcha/api/siteverify');
    if ($curl === false) {
        error_log('Water Go could not initialize reCAPTCHA verification.');
        return 'unavailable';
    }
    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'secret' => $keys['secret'],
            'response' => $response,
            'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
        ]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $body = curl_exec($curl);
    $httpStatus = (int)curl_getinfo($curl, CURLINFO_HTTP_CODE);
    $curlError = curl_error($curl);
    curl_close($curl);

    if (!is_string($body) || $httpStatus !== 200) {
        error_log('Water Go reCAPTCHA verification request failed: ' . ($curlError !== '' ? $curlError : 'HTTP ' . $httpStatus));
        return 'unavailable';
    }

    $result = json_decode($body, true);
    if (!is_array($result) || !array_key_exists('success', $result)) {
        error_log('Water Go received an invalid response from reCAPTCHA verification.');
        return 'unavailable';
    }

    return $result['success'] === true ? 'verified' : 'invalid';
}
