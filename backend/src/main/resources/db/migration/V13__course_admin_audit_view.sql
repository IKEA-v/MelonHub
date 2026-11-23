-- Grant the course business permission in the same department and application as the admin role.
INSERT INTO permissions(department_id, application_id, name, code, resource, action)
SELECT r.department_id, r.application_id, '查看课程日志', 'AV', 'audit', 'view'
FROM roles r JOIN applications a ON a.id = r.application_id
WHERE a.code = 'course-project-management' AND r.code = 'admin'
  AND NOT EXISTS (SELECT 1 FROM permissions p
                  WHERE p.department_id = r.department_id AND p.application_id = r.application_id AND p.code = 'AV');

INSERT INTO role_permissions(role_id, permission_id, department_id, application_id)
SELECT r.id, p.id, r.department_id, r.application_id
FROM roles r JOIN applications a ON a.id = r.application_id
JOIN permissions p ON p.department_id = r.department_id AND p.application_id = r.application_id AND p.code = 'AV'
WHERE a.code = 'course-project-management' AND r.code = 'admin'
  AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id = r.id AND rp.permission_id = p.id);
