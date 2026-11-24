CREATE DATABASE IF NOT EXISTS water_go CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE water_go;

CREATE TABLE users (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(500) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('admin','staff') NOT NULL DEFAULT 'staff',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE staff_registration_profiles (
  id_number VARCHAR(9) NOT NULL PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL UNIQUE,
  username VARCHAR(20) NOT NULL UNIQUE,
  first_name VARCHAR(50) NOT NULL,
  middle_name VARCHAR(50) NULL,
  family_name VARCHAR(50) NOT NULL,
  name_extension VARCHAR(50) NULL,
  emergency_contact VARCHAR(11) NOT NULL,
  birthdate DATE NOT NULL,
  purok_street VARCHAR(50) NOT NULL,
  barangay VARCHAR(50) NOT NULL,
  municipality_city VARCHAR(50) NOT NULL,
  province VARCHAR(50) NOT NULL,
  country VARCHAR(100) NOT NULL,
  zip_code CHAR(4) NOT NULL,
  security_question_1 VARCHAR(2) NOT NULL,
  security_answer_1_hash VARCHAR(255) NOT NULL,
  security_question_2 VARCHAR(2) NOT NULL,
  security_answer_2_hash VARCHAR(255) NOT NULL,
  security_question_3 VARCHAR(2) NOT NULL,
  security_answer_3_hash VARCHAR(255) NOT NULL,
  privacy_consent_at DATETIME NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE auth_login_state (
  identifier_hash CHAR(64) NOT NULL PRIMARY KEY,
  failed_count TINYINT UNSIGNED NOT NULL DEFAULT 0,
  lockout_tier TINYINT UNSIGNED NOT NULL DEFAULT 0,
  lockout_until DATETIME NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE auth_login_attempts (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  identifier_hash CHAR(64) NOT NULL,
  ip_address VARBINARY(16) NOT NULL,
  attempt_at DATETIME NOT NULL,
  INDEX idx_login_attempt_ip_time (ip_address, attempt_at),
  INDEX idx_login_attempt_identifier_time (identifier_hash, attempt_at)
);

CREATE TABLE auth_login_otps (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  code_hash VARCHAR(255) NOT NULL,
  attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  request_ip VARBINARY(16) NOT NULL,
  created_at DATETIME NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_login_otp_user_time (user_id, created_at),
  INDEX idx_login_otp_expiry (expires_at, used_at)
);

CREATE TABLE security_events (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(40) NOT NULL,
  username_typed TEXT NULL,
  user_id INT UNSIGNED NULL,
  ip_address VARCHAR(45) NULL,
  user_agent VARCHAR(512) NOT NULL DEFAULT '',
  details TEXT NOT NULL,
  created_at DATETIME NOT NULL,
  INDEX idx_security_event_time (created_at, id),
  INDEX idx_security_event_type_time (event_type, created_at),
  INDEX idx_security_event_ip_time (ip_address, created_at),
  INDEX idx_security_event_user_time (user_id, created_at)
);

CREATE TABLE security_flags (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  flag_type VARCHAR(40) NOT NULL,
  severity ENUM('Low','Medium','High') NOT NULL,
  target_key VARCHAR(255) NOT NULL,
  affected_target VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  detected_at DATETIME NOT NULL,
  detected_day DATE NOT NULL,
  UNIQUE KEY uq_security_flag_daily_target (flag_type, target_key, detected_day),
  INDEX idx_security_flag_detected (detected_at, id)
);

CREATE TABLE password_reset_otps (
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

CREATE TABLE customers (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(120) NOT NULL,
  phone VARCHAR(30),
  address TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  product_name VARCHAR(120) NOT NULL,
  size VARCHAR(50),
  price DECIMAL(10,2) NOT NULL DEFAULT 0,
  quantity INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  order_code VARCHAR(30) NOT NULL UNIQUE,
  customer_id INT UNSIGNED NULL,
  product_name VARCHAR(120) NOT NULL,
  quantity INT NOT NULL DEFAULT 1,
  status ENUM('Pending','Processing','Completed','Cancelled') NOT NULL DEFAULT 'Pending',
  assigned_to INT UNSIGNED NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
  FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
);

DELIMITER //
CREATE OR REPLACE TRIGGER security_events_no_update
BEFORE UPDATE ON security_events
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Security events are append-only';
END//

CREATE OR REPLACE TRIGGER security_events_no_delete
BEFORE DELETE ON security_events
FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Security events are append-only';
END//
DELIMITER ;

-- Create administrator accounts directly in the database with a locally generated password hash.

INSERT INTO customers (full_name,phone,address) VALUES
('Jamie Rivera','09171234567','Cabadbaran City'),
('Alex Santos','09181234567','Cabadbaran City'),
('Morgan Reyes','09191234567','Cabadbaran City');

INSERT INTO products (product_name,size,price,quantity) VALUES
('Purified Water','5 Gallon',35.00,80),
('Mineral Water','5 Gallon',40.00,55),
('Alkaline Water','5 Gallon',45.00,30);
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

ALTER TABLE users ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 1;
ALTER TABLE staff_registration_profiles MODIFY emergency_contact VARCHAR(255) NOT NULL;
CREATE TABLE IF NOT EXISTS registration_otps LIKE auth_login_otps;


ALTER TABLE auth_login_otps ADD COLUMN is_resend TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE password_reset_otps ADD COLUMN is_resend TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE registration_otps ADD COLUMN is_resend TINYINT(1) NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS admin_recovery_questions (
  user_id INT UNSIGNED NOT NULL,
  question_id VARCHAR(2) NOT NULL,
  answer_hash VARCHAR(255) NOT NULL,
  PRIMARY KEY (user_id, question_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_username VARCHAR(20) NULL UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_totp_secret VARCHAR(255) NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_totp_last_step BIGINT UNSIGNED NULL;
ALTER TABLE auth_login_otps ADD COLUMN IF NOT EXISTS verified_at DATETIME NULL;
