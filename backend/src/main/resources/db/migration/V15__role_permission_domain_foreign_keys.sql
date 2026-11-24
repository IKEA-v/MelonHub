-- Remove relationships that cannot be valid under the current department × application model.
DELETE rp
FROM role_permissions rp
LEFT JOIN roles r ON r.id = rp.role_id
LEFT JOIN permissions p ON p.id = rp.permission_id
WHERE r.id IS NULL OR p.id IS NULL
   OR rp.department_id <> r.department_id
   OR rp.application_id <> r.application_id
   OR rp.department_id <> p.department_id
   OR rp.application_id <> p.application_id;

ALTER TABLE role_permissions MODIFY department_id BIGINT NOT NULL;

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.statistics
     WHERE table_schema = DATABASE() AND table_name = 'roles' AND index_name = 'uq_roles_id_domain') = 0,
    'ALTER TABLE roles ADD UNIQUE KEY uq_roles_id_domain (id,department_id,application_id)',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.statistics
     WHERE table_schema = DATABASE() AND table_name = 'permissions' AND index_name = 'uq_permissions_id_domain') = 0,
    'ALTER TABLE permissions ADD UNIQUE KEY uq_permissions_id_domain (id,department_id,application_id)',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.referential_constraints
     WHERE constraint_schema = DATABASE() AND table_name = 'role_permissions'
       AND constraint_name = 'fk_role_permissions_role_domain') = 0,
    'ALTER TABLE role_permissions ADD CONSTRAINT fk_role_permissions_role_domain
       FOREIGN KEY (role_id,department_id,application_id)
       REFERENCES roles(id,department_id,application_id) ON DELETE CASCADE',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.referential_constraints
     WHERE constraint_schema = DATABASE() AND table_name = 'role_permissions'
       AND constraint_name = 'fk_role_permissions_permission_domain') = 0,
    'ALTER TABLE role_permissions ADD CONSTRAINT fk_role_permissions_permission_domain
       FOREIGN KEY (permission_id,department_id,application_id)
       REFERENCES permissions(id,department_id,application_id) ON DELETE CASCADE',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;
