ALTER TABLE departments
    ADD COLUMN parent_id BIGINT NULL,
    ADD CONSTRAINT fk_departments_parent FOREIGN KEY (parent_id) REFERENCES departments(id);

CREATE TABLE identity_credentials (
    user_id BIGINT PRIMARY KEY,
    username VARCHAR(128) NOT NULL COLLATE utf8mb4_bin UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE identity_sessions (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    token_hash VARCHAR(64) NOT NULL COLLATE utf8mb4_bin UNIQUE,
    user_id BIGINT NOT NULL,
    audience VARCHAR(128) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX ix_identity_sessions_user (user_id, expires_at),
    INDEX ix_identity_sessions_expiry (expires_at, revoked_at)
) ENGINE=InnoDB;
