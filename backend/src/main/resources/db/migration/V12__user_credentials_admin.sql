INSERT INTO admin_functions(code, name, category, sort_order) VALUES
 ('user.delete', '永久删除用户', '组织与软件', 31),
 ('user.credentials', '管理用户登录凭据', '组织与软件', 32),
 ('user.status', '启停用户与强制下线', '组织与软件', 33);

-- Preserve the status and deletion permissions that were formerly part of user.manage.
INSERT INTO admin_role_functions(role_code, function_code)
 SELECT role_code, 'user.delete' FROM admin_role_functions WHERE function_code = 'user.manage';
INSERT INTO admin_role_functions(role_code, function_code)
 SELECT role_code, 'user.status' FROM admin_role_functions WHERE function_code = 'user.manage';

INSERT INTO admin_role_functions(role_code, function_code) VALUES
 ('SUPER_ADMIN', 'user.credentials'), ('ADMIN', 'user.credentials');
DELETE FROM admin_role_functions WHERE function_code = 'user.manage' AND role_code NOT IN ('SUPER_ADMIN', 'ADMIN');
UPDATE admin_functions SET name = '新建与编辑用户' WHERE code = 'user.manage';

INSERT INTO admin_roles(code, name, description, builtin) VALUES
 ('DEPARTMENT_ADMIN', '部门管理员', '启停所管部门的用户并管理授权', TRUE);

INSERT INTO admin_role_functions(role_code, function_code)
 SELECT 'DEPARTMENT_ADMIN', function_code FROM admin_role_functions
 WHERE role_code = 'APP_ADMIN' AND function_code <> 'application.credentials';
INSERT INTO admin_role_functions(role_code, function_code) VALUES ('DEPARTMENT_ADMIN', 'user.status');

-- A department leaf can only receive functions held by its parent.
UPDATE admin_accounts child JOIN admin_accounts parent ON parent.username = child.parent_username
 SET child.role = 'DEPARTMENT_ADMIN', child.all_applications = TRUE
 WHERE child.kind = 'DEPARTMENT' AND child.role = 'APP_ADMIN'
   AND parent.role IN ('SUPER_ADMIN', 'ADMIN') AND parent.all_applications = TRUE;

DELETE scope FROM admin_account_applications scope JOIN admin_accounts account ON account.username = scope.username
 WHERE account.role = 'DEPARTMENT_ADMIN' AND account.all_applications = TRUE;
