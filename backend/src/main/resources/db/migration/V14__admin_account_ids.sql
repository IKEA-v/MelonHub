-- Allocate IDs and copy every administrator relationship before dropping the username keys.
ALTER TABLE admin_accounts
  ADD COLUMN id BIGINT NOT NULL AUTO_INCREMENT,
  ADD UNIQUE KEY uq_admin_accounts_id (id),
  ADD UNIQUE KEY uq_admin_accounts_username (username),
  ADD COLUMN parent_id BIGINT NULL;
ALTER TABLE admin_sessions ADD COLUMN account_id BIGINT NULL;
ALTER TABLE admin_account_departments ADD COLUMN account_id BIGINT NULL;
ALTER TABLE admin_account_applications ADD COLUMN account_id BIGINT NULL;

UPDATE admin_accounts child JOIN admin_accounts parent ON parent.username = child.parent_username
  SET child.parent_id = parent.id;
UPDATE admin_sessions s JOIN admin_accounts a ON a.username = s.username SET s.account_id = a.id;
UPDATE admin_account_departments s JOIN admin_accounts a ON a.username = s.username SET s.account_id = a.id;
UPDATE admin_account_applications s JOIN admin_accounts a ON a.username = s.username SET s.account_id = a.id;

ALTER TABLE admin_sessions DROP FOREIGN KEY fk_admin_sessions_account;
ALTER TABLE admin_account_departments DROP FOREIGN KEY fk_account_departments_account;
ALTER TABLE admin_account_applications DROP FOREIGN KEY fk_account_apps_account;
ALTER TABLE admin_accounts DROP FOREIGN KEY fk_admin_accounts_parent;

ALTER TABLE admin_accounts
  DROP PRIMARY KEY, ADD PRIMARY KEY (id), DROP INDEX uq_admin_accounts_id,
  DROP INDEX idx_admin_accounts_parent, DROP COLUMN parent_username,
  ADD INDEX idx_admin_accounts_parent (parent_id),
  ADD CONSTRAINT fk_admin_accounts_parent_id FOREIGN KEY (parent_id) REFERENCES admin_accounts(id);
ALTER TABLE admin_sessions
  MODIFY account_id BIGINT NOT NULL, DROP INDEX idx_admin_sessions_user, DROP COLUMN username,
  ADD INDEX idx_admin_sessions_account (account_id),
  ADD CONSTRAINT fk_admin_sessions_account_id FOREIGN KEY (account_id) REFERENCES admin_accounts(id) ON DELETE CASCADE;
ALTER TABLE admin_account_departments
  MODIFY account_id BIGINT NOT NULL, DROP PRIMARY KEY, DROP COLUMN username,
  ADD PRIMARY KEY (account_id, department_id),
  ADD CONSTRAINT fk_account_departments_account_id FOREIGN KEY (account_id) REFERENCES admin_accounts(id) ON DELETE CASCADE;
ALTER TABLE admin_account_applications
  MODIFY account_id BIGINT NOT NULL, DROP PRIMARY KEY, DROP COLUMN username,
  ADD PRIMARY KEY (account_id, application_id),
  ADD CONSTRAINT fk_account_apps_account_id FOREIGN KEY (account_id) REFERENCES admin_accounts(id) ON DELETE CASCADE;
