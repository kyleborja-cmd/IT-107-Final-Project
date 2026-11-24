CREATE TABLE IF NOT EXISTS admin_recovery_questions (
  user_id INT UNSIGNED NOT NULL,
  question_id VARCHAR(2) NOT NULL,
  answer_hash VARCHAR(255) NOT NULL,
  PRIMARY KEY (user_id, question_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
