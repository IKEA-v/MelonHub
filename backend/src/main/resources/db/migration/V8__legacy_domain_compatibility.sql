-- 服务器早期版本的 V6/V7 将角色和权限改成了按软件共享。
-- 当前模型要求它们属于“部门 × 软件”域。新库已经有 department_id，以下迁移在新库中只做幂等校验，
-- 在旧库中按已有授权关系拆分角色和权限，保留用户已有的有效授权。

SET @legacy_domain_model := (
    SELECT COUNT(*) = 0
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'roles' AND column_name = 'department_id'
);

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'roles' AND column_name = 'department_id') = 0,
    'ALTER TABLE roles ADD COLUMN department_id BIGINT NULL',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'permissions' AND column_name = 'department_id') = 0,
    'ALTER TABLE permissions ADD COLUMN department_id BIGINT NULL',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'role_permissions' AND column_name = 'department_id') = 0,
    'ALTER TABLE role_permissions ADD COLUMN department_id BIGINT NULL',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(@legacy_domain_model AND (SELECT COUNT(*) FROM information_schema.referential_constraints
                                         WHERE constraint_schema = DATABASE() AND table_name = 'role_permissions'
                                           AND constraint_name = 'fk_role_permission_role') > 0,
    'ALTER TABLE role_permissions DROP FOREIGN KEY fk_role_permission_role',
    'SELECT 1');
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(@legacy_domain_model AND (SELECT COUNT(*) FROM information_schema.referential_constraints
                                         WHERE constraint_schema = DATABASE() AND table_name = 'role_permissions'
                                           AND constraint_name = 'fk_role_permission_application') > 0,
    'ALTER TABLE role_permissions DROP FOREIGN KEY fk_role_permission_application',
    'SELECT 1');
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(@legacy_domain_model AND (SELECT COUNT(*) FROM information_schema.referential_constraints
                                         WHERE constraint_schema = DATABASE() AND table_name = 'user_roles'
                                           AND constraint_name = 'fk_assignment_role') > 0,
    'ALTER TABLE user_roles DROP FOREIGN KEY fk_assignment_role',
    'SELECT 1');
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(@legacy_domain_model AND (SELECT COUNT(*) FROM information_schema.statistics
                                         WHERE table_schema = DATABASE() AND table_name = 'roles'
                                           AND index_name = 'idx_roles_application_id') = 0,
    'ALTER TABLE roles ADD INDEX idx_roles_application_id(application_id)',
    'SELECT 1');
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(
    @legacy_domain_model,
    'ALTER TABLE roles DROP INDEX uq_role_application_code',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(@legacy_domain_model AND (SELECT COUNT(*) FROM information_schema.statistics
                                         WHERE table_schema = DATABASE() AND table_name = 'permissions'
                                           AND index_name = 'idx_permissions_application_id') = 0,
    'ALTER TABLE permissions ADD INDEX idx_permissions_application_id(application_id)',
    'SELECT 1');
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(
    @legacy_domain_model,
    'ALTER TABLE permissions DROP INDEX uq_permission_application_code',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

CREATE TEMPORARY TABLE legacy_role_departments (
    old_role_id BIGINT NOT NULL,
    department_id BIGINT NOT NULL,
    PRIMARY KEY (old_role_id, department_id)
);
INSERT INTO legacy_role_departments(old_role_id, department_id)
SELECT ur.role_id, ur.department_id
FROM user_roles ur
WHERE @legacy_domain_model AND ur.department_id IS NOT NULL
GROUP BY ur.role_id, ur.department_id;
CREATE TEMPORARY TABLE legacy_role_has_department AS
SELECT old_role_id FROM legacy_role_departments GROUP BY old_role_id;
INSERT INTO legacy_role_departments(old_role_id, department_id)
SELECT r.id, (SELECT MIN(id) FROM departments)
FROM roles r
WHERE @legacy_domain_model
  AND NOT EXISTS (SELECT 1 FROM legacy_role_has_department m WHERE m.old_role_id = r.id);

UPDATE roles r
JOIN (
    SELECT old_role_id, MIN(department_id) AS department_id
    FROM legacy_role_departments
    GROUP BY old_role_id
) m ON m.old_role_id = r.id
SET r.department_id = m.department_id
WHERE @legacy_domain_model;

INSERT INTO roles(department_id, application_id, name, code, description, enabled, created_at)
SELECT m.department_id, r.application_id, r.name, r.code, r.description, r.enabled, r.created_at
FROM legacy_role_departments m
JOIN roles r ON r.id = m.old_role_id
WHERE @legacy_domain_model AND m.department_id <> r.department_id;

CREATE TEMPORARY TABLE legacy_role_map (
    old_role_id BIGINT NOT NULL,
    department_id BIGINT NOT NULL,
    new_role_id BIGINT NOT NULL,
    PRIMARY KEY (old_role_id, department_id)
);
INSERT INTO legacy_role_map(old_role_id, department_id, new_role_id)
SELECT m.old_role_id, m.department_id, r.id
FROM legacy_role_departments m
JOIN roles old_role ON old_role.id = m.old_role_id
JOIN roles r ON r.application_id = old_role.application_id
            AND r.code = old_role.code
            AND r.department_id = m.department_id;

CREATE TEMPORARY TABLE legacy_user_roles AS
SELECT user_id, role_id AS old_role_id, department_id, application_id, expires_at, granted_by, granted_at, grant_id
FROM user_roles;
UPDATE legacy_user_roles
SET department_id = (SELECT MIN(id) FROM departments)
WHERE @legacy_domain_model AND department_id IS NULL;
DELETE FROM user_roles WHERE @legacy_domain_model;
INSERT INTO user_roles(user_id, role_id, department_id, application_id, expires_at, granted_by, granted_at, grant_id)
SELECT ur.user_id, COALESCE(rm.new_role_id, ur.old_role_id), ur.department_id, ur.application_id,
       ur.expires_at, ur.granted_by, ur.granted_at, ur.grant_id
FROM legacy_user_roles ur
LEFT JOIN legacy_role_map rm ON rm.old_role_id = ur.old_role_id AND rm.department_id = ur.department_id
WHERE @legacy_domain_model;

CREATE TEMPORARY TABLE legacy_permission_departments (
    old_permission_id BIGINT NOT NULL,
    department_id BIGINT NOT NULL,
    PRIMARY KEY (old_permission_id, department_id)
);
INSERT INTO legacy_permission_departments(old_permission_id, department_id)
SELECT rp.permission_id, rm.department_id
FROM role_permissions rp
JOIN legacy_role_map rm ON rm.old_role_id = rp.role_id
WHERE @legacy_domain_model
GROUP BY rp.permission_id, rm.department_id;
CREATE TEMPORARY TABLE legacy_permission_has_department AS
SELECT old_permission_id FROM legacy_permission_departments GROUP BY old_permission_id;
INSERT INTO legacy_permission_departments(old_permission_id, department_id)
SELECT p.id, (SELECT MIN(id) FROM departments)
FROM permissions p
WHERE @legacy_domain_model
  AND NOT EXISTS (SELECT 1 FROM legacy_permission_has_department m WHERE m.old_permission_id = p.id);

UPDATE permissions p
JOIN (
    SELECT old_permission_id, MIN(department_id) AS department_id
    FROM legacy_permission_departments
    GROUP BY old_permission_id
) m ON m.old_permission_id = p.id
SET p.department_id = m.department_id
WHERE @legacy_domain_model;

INSERT INTO permissions(department_id, application_id, name, code, resource, action, created_at)
SELECT m.department_id, p.application_id, p.name, p.code, p.resource, p.action, p.created_at
FROM legacy_permission_departments m
JOIN permissions p ON p.id = m.old_permission_id
WHERE @legacy_domain_model AND m.department_id <> p.department_id;

CREATE TEMPORARY TABLE legacy_permission_map (
    old_permission_id BIGINT NOT NULL,
    department_id BIGINT NOT NULL,
    new_permission_id BIGINT NOT NULL,
    PRIMARY KEY (old_permission_id, department_id)
);
INSERT INTO legacy_permission_map(old_permission_id, department_id, new_permission_id)
SELECT m.old_permission_id, m.department_id, p.id
FROM legacy_permission_departments m
JOIN permissions old_permission ON old_permission.id = m.old_permission_id
JOIN permissions p ON p.application_id = old_permission.application_id
                 AND p.code = old_permission.code
                 AND p.department_id = m.department_id;

CREATE TEMPORARY TABLE legacy_role_permissions AS
SELECT role_id AS old_role_id, permission_id AS old_permission_id, application_id
FROM role_permissions;
DELETE FROM role_permissions WHERE @legacy_domain_model;
INSERT INTO role_permissions(role_id, permission_id, department_id, application_id)
SELECT rm.new_role_id, pm.new_permission_id, rm.department_id, rp.application_id
FROM legacy_role_permissions rp
JOIN legacy_role_map rm ON rm.old_role_id = rp.old_role_id
JOIN legacy_permission_map pm ON pm.old_permission_id = rp.old_permission_id
                            AND pm.department_id = rm.department_id
WHERE @legacy_domain_model;

ALTER TABLE roles MODIFY department_id BIGINT NOT NULL;
ALTER TABLE permissions MODIFY department_id BIGINT NOT NULL;
ALTER TABLE role_permissions MODIFY department_id BIGINT NOT NULL;

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'roles' AND index_name = 'uq_roles_domain_code') = 0,
    'ALTER TABLE roles ADD UNIQUE KEY uq_roles_domain_code (department_id, application_id, code)',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'permissions' AND index_name = 'uq_permissions_domain_code') = 0,
    'ALTER TABLE permissions ADD UNIQUE KEY uq_permissions_domain_code (department_id, application_id, code)',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

DROP TEMPORARY TABLE legacy_role_permissions;
DROP TEMPORARY TABLE legacy_permission_map;
DROP TEMPORARY TABLE legacy_permission_has_department;
DROP TEMPORARY TABLE legacy_permission_departments;
DROP TEMPORARY TABLE legacy_user_roles;
DROP TEMPORARY TABLE legacy_role_has_department;
DROP TEMPORARY TABLE legacy_role_map;
DROP TEMPORARY TABLE legacy_role_departments;
