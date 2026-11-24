package com.melonhub.rbac.service.ddd.domain.value;

import java.util.Set;

/**
 * 管理员管辖范围值对象：封装部门范围与软件范围的包含关系与审计描述。
 */
public record AdminScope(boolean allDepartments, Set<Long> departments, boolean allApplications, Set<Long> applications) {
    public AdminScope {
        departments = allDepartments || departments == null ? Set.of() : Set.copyOf(departments);
        applications = allApplications || applications == null ? Set.of() : Set.copyOf(applications);
    }

    public static AdminScope unrestricted() {
        return new AdminScope(true, Set.of(), true, Set.of());
    }

    public boolean coversDepartmentsOf(AdminScope child) {
        return allDepartments || (!child.allDepartments && departments.containsAll(child.departments));
    }

    public boolean coversApplicationsOf(AdminScope child) {
        return allApplications || (!child.allApplications && applications.containsAll(child.applications));
    }

    public String auditDetail() {
        return (allDepartments ? "" : "，管理部门 " + departments.size() + " 个")
                + (allApplications ? "" : "，授权软件 " + applications.size() + " 个");
    }
}
