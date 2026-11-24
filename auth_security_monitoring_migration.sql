USE water_go;

CREATE TABLE IF NOT EXISTS auth_login_otps (
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

CREATE TABLE IF NOT EXISTS security_events (
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

CREATE TABLE IF NOT EXISTS security_flags (
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
