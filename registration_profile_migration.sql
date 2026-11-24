USE water_go;

-- Check these results before running the ALTER statements. Resolve any rows that
-- exceed the new limits without truncating existing account data.
SELECT id, email FROM users WHERE CHAR_LENGTH(email) > 100;
SELECT id_number, username, first_name, middle_name, family_name, name_extension
FROM staff_registration_profiles
WHERE CHAR_LENGTH(username) > 20
   OR CHAR_LENGTH(first_name) > 50
   OR CHAR_LENGTH(middle_name) > 50
   OR CHAR_LENGTH(family_name) > 50
   OR CHAR_LENGTH(name_extension) > 50;

ALTER TABLE users MODIFY email VARCHAR(100) NOT NULL;
ALTER TABLE staff_registration_profiles
  MODIFY username VARCHAR(20) NOT NULL,
  MODIFY first_name VARCHAR(50) NOT NULL,
  MODIFY middle_name VARCHAR(50) NULL,
  MODIFY family_name VARCHAR(50) NOT NULL,
  MODIFY name_extension VARCHAR(50) NULL;

CREATE TABLE IF NOT EXISTS auth_login_state (
  identifier_hash CHAR(64) NOT NULL PRIMARY KEY,
  failed_count TINYINT UNSIGNED NOT NULL DEFAULT 0,
  lockout_tier TINYINT UNSIGNED NOT NULL DEFAULT 0,
  lockout_until DATETIME NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_login_attempts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  identifier_hash CHAR(64) NOT NULL,
  ip_address VARBINARY(16) NOT NULL,
  attempt_at DATETIME NOT NULL,
  INDEX idx_login_attempt_ip_time (ip_address, attempt_at),
  INDEX idx_login_attempt_identifier_time (identifier_hash, attempt_at)
);

CREATE TABLE IF NOT EXISTS password_reset_otps (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  code_hash VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
  used_at DATETIME NULL,
  request_ip VARBINARY(16) NOT NULL,
  created_at DATETIME NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_reset_otp_user_time (user_id, created_at),
  INDEX idx_reset_otp_ip_time (request_ip, created_at)
);
