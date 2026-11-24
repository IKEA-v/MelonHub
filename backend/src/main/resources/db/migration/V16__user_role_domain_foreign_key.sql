-- User role assignments must point to a role in the same department and software.
ALTER TABLE user_roles DROP FOREIGN KEY fk_assignment_origin;
ALTER TABLE user_roles ADD CONSTRAINT fk_assignment_origin
    FOREIGN KEY (department_id) REFERENCES departments(id);
ALTER TABLE user_roles ADD CONSTRAINT ck_user_roles_department_not_null CHECK (department_id IS NOT NULL);

SET @sql := IF(
    (SELECT COUNT(*) FROM information_schema.referential_constraints
     WHERE constraint_schema = DATABASE() AND table_name = 'user_roles'
       AND constraint_name = 'fk_user_roles_role_domain') = 0,
    'ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_role_domain
       FOREIGN KEY (role_id,department_id,application_id)
       REFERENCES roles(id,department_id,application_id) ON DELETE CASCADE',
    'SELECT 1'
);
PREPARE melonhub_stmt FROM @sql;
EXECUTE melonhub_stmt;
DEALLOCATE PREPARE melonhub_stmt;
