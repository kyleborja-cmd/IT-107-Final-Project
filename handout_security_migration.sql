CREATE TABLE IF NOT EXISTS auth_ip_blocks (
  ip_address VARBINARY(16) NOT NULL PRIMARY KEY,
  blocked_until DATETIME NOT NULL,
  INDEX idx_auth_ip_block_expiry (blocked_until)
);

CREATE TABLE IF NOT EXISTS password_history (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_password_history_user (user_id, id)
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified TINYINT(1) NOT NULL DEFAULT 1;
ALTER TABLE staff_registration_profiles MODIFY emergency_contact VARCHAR(255) NOT NULL;

CREATE TABLE IF NOT EXISTS registration_otps LIKE auth_login_otps;


ALTER TABLE auth_login_otps ADD COLUMN IF NOT EXISTS is_resend TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE password_reset_otps ADD COLUMN IF NOT EXISTS is_resend TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE registration_otps ADD COLUMN IF NOT EXISTS is_resend TINYINT(1) NOT NULL DEFAULT 0;
