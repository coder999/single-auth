-- migrate:up
CREATE TABLE user_credentials (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id       INT UNSIGNED NOT NULL,
  credential_id VARCHAR(255) NOT NULL,
  public_key    TEXT NOT NULL,
  sign_count    INT UNSIGNED NOT NULL DEFAULT 0,
  transports    VARCHAR(255) NULL,
  label         VARCHAR(64) NOT NULL,
  created_at    DATETIME NOT NULL,
  last_used_at  DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_credential_id (credential_id),
  KEY idx_user (user_id),
  CONSTRAINT fk_user_credentials_user FOREIGN KEY (user_id)
    REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

ALTER TABLE users ADD COLUMN webauthn_user_handle VARCHAR(64) NULL,
  ADD UNIQUE KEY uniq_webauthn_user_handle (webauthn_user_handle);

-- migrate:down
ALTER TABLE users DROP INDEX uniq_webauthn_user_handle,
  DROP COLUMN webauthn_user_handle;
DROP TABLE user_credentials;
