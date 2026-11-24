package com.melonhub.rbac.service.ddd.domain.value;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 课程管理系统统一身份对接的权限目录与角色规范化值对象。
 */
public final class CoursePermissionCatalog {
    public static final String COURSE_SYSTEM = "course-project-management";
    public static final String PERMISSION_ORG_VIEW = "ORG_VIEW";
    public static final String PERMISSION_TEACHER_EDIT = "TEC";
    public static final String PERMISSION_AUDIT_VIEW = "AV";

    private static final Map<String, String> API_PERMISSIONS = Map.ofEntries(
            Map.entry("listTerms", "CV"),
            Map.entry("createTerm", "TC"),
            Map.entry("updateTerm", "TE"),
            Map.entry("deleteTerm", "TD"),
            Map.entry("setCurrentTerm", "TCM"),
            Map.entry("cancelCurrentTerm", "TCM"),
            Map.entry("getCourse", "CV"),
            Map.entry("createCourse", "CE"),
            Map.entry("submitCourseReview", "CR"),
            Map.entry("reviewCourse", "CR"),
            Map.entry("updateCourse", "CE"),
            Map.entry("deleteCourse", "CD"),
            Map.entry("copyCourse", "CC"),
            Map.entry("setCourseLeaders", "CTM"),
            Map.entry("listAdminCourses", "CV"),
            Map.entry("listTeachers", "TV"),
            Map.entry("createTeacher", "TEC"),
            Map.entry("updateTeacher", "TEE"),
            Map.entry("deleteTeacher", "TED"),
            Map.entry("queryAuditLogs", PERMISSION_AUDIT_VIEW),
            Map.entry("listAuditLogs", PERMISSION_AUDIT_VIEW)
    );

    private CoursePermissionCatalog() {}

    public static String requirePermissionForOperation(String operationId) {
        String permission = API_PERMISSIONS.get(operationId);
        if (permission == null) {
            throw new DomainException(DomainException.Kind.NOT_FOUND, "API_OPERATION_NOT_FOUND", "没有找到对应的 API 操作。");
        }
        return permission;
    }

    public static List<String> normalizeRoles(List<String> rawRoles) {
        return rawRoles.stream().map(role -> role.toLowerCase(Locale.ROOT)).toList();
    }

    public static boolean canReadOrganizations(List<String> rawRoles, List<String> permissions) {
        return permissions.contains(PERMISSION_ORG_VIEW) || rawRoles.contains("admin");
    }

    public static boolean canLookupUsers(List<String> rawRoles, List<String> permissions) {
        return permissions.contains(PERMISSION_TEACHER_EDIT) || rawRoles.contains("admin");
    }
}
