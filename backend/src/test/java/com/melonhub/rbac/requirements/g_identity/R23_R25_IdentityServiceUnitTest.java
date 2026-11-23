package com.melonhub.rbac.requirements.g_identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.melonhub.rbac.dao.IdentityDao;
import com.melonhub.rbac.dao.RbacDao;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.identity.IdentityService;
import com.melonhub.rbac.identity.IdentityTokenService;
import com.melonhub.rbac.security.AdminFunction;
import com.melonhub.rbac.security.AdminPrincipal;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.service.RbacService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 对应需求：R23、R24、R25（见 doc/requirements.md）。
 * 统一身份登录退出、当前用户、菜单/按钮/API 全局权限、组织架构查询及课程审计日志隔离的纯单元测试。
 */
class R23_R25_IdentityServiceUnitTest {

    private static final String SYSTEM = "course-project-management";

    private final IdentityDao identityDao = mock(IdentityDao.class);
    private final RbacService rbacService = mock(RbacService.class);
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private final IdentityTokenService tokenService = new IdentityTokenService(
            "unit-test-secret-unit-test-secret-32",
            "https://identity.test",
            7200
    );
    private final IdentityService service = new IdentityService(identityDao, rbacService, encoder, tokenService);

    @Test
    @DisplayName("R23 统一身份登录校验目标系统与密码、签发 JWT 并在凭据未变时建立会话")
    void loginIssuesJwtAndCreatesSessionWithCredentialCheck() {
        String hash = encoder.encode("CoursePass!2026");
        var row = new IdentityDao.CredentialRow(10L, "SG000001", hash);
        when(identityDao.credential("SG000001")).thenReturn(Optional.of(row));
        when(identityDao.createSession(any(), eq(row), eq(SYSTEM), any())).thenReturn(true);

        Map<String, Object> result = service.login("SG000001", "CoursePass!2026", List.of(SYSTEM));
        assertThat(result.get("tokenType")).isEqualTo("Bearer");
        assertThat(result.get("expiresIn")).isEqualTo(7200L);
        String token = (String) result.get("accessToken");
        assertThat(tokenService.verify(token, SYSTEM).subject()).isEqualTo("SG000001");

        // 缺少课程系统标识返回 400
        assertThatThrownBy(() -> service.login("SG000001", "CoursePass!2026", List.of("other-app")))
                .isInstanceOf(ApiException.class)
                .extracting("status").isEqualTo(HttpStatus.BAD_REQUEST);

        // 密码错误返回 401
        assertThatThrownBy(() -> service.login("SG000001", "WrongPass", List.of(SYSTEM)))
                .isInstanceOf(ApiException.class)
                .extracting("status").isEqualTo(HttpStatus.UNAUTHORIZED);

        // 并发改密/停用导致共享锁建会话失败返回 401
        when(identityDao.createSession(any(), eq(row), eq(SYSTEM), any())).thenReturn(false);
        assertThatThrownBy(() -> service.login("SG000001", "CoursePass!2026", List.of(SYSTEM)))
                .isInstanceOf(ApiException.class)
                .extracting("status").isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("R23 退出登录撤销当前 JWT 会话，重置统一身份密码校验长度并撤销全部会话")
    void logoutRevokesActiveTokenAndSetPasswordRevokesAllSessions() {
        String token = tokenService.issue("SG000001", List.of(SYSTEM), Instant.now());
        service.logout("Bearer " + token);
        verify(identityDao).revokeSession(eq(Credentials.hash(token)), any(Instant.class));

        AdminPrincipal superAdmin = new AdminPrincipal(1L, "admin", "超管", AdminPrincipal.SUPER_ADMIN, "超级管理员",
                Set.of(AdminFunction.USER_CREDENTIALS), true, AdminPrincipal.MANAGER, true, Set.of(), true, Set.of());
        when(rbacService.lockOwnedUser(10L, null)).thenReturn("SG000001");

        service.setUserPassword(10L, "NewCoursePass!2026", superAdmin);
        verify(identityDao).upsertCredential(eq(10L), eq("SG000001"), any(String.class));
        verify(identityDao).revokeUserSessions(10L);
        verify(rbacService).audit("admin", "USER_IDENTITY_PASSWORD_SET", "SG000001", null, null, "统一身份会话已结束");

        // 超过 72 UTF-8 字节的统一身份密码必须拒绝
        String over72 = "a".repeat(73);
        assertThatThrownBy(() -> service.setUserPassword(10L, over72, superAdmin))
                .isInstanceOf(ApiException.class)
                .extracting("status").isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("R24 查询当前用户实时角色与权限、前端权限码及 21 项 API operationId 映射")
    void currentUserAndPermissionEndpointsQueryLiveAuthorizations() {
        String token = tokenService.issue("SG000001", List.of(SYSTEM), Instant.now());
        String auth = "Bearer " + token;
        when(identityDao.activeSession(eq(Credentials.hash(token)), any())).thenReturn(true);
        when(identityDao.userByExternalId("SG000001"))
                .thenReturn(Optional.of(new IdentityDao.UserRow(10L, "SG000001", "张老师")));
        when(identityDao.roles(10L, SYSTEM)).thenReturn(List.of("Teacher"));
        when(identityDao.permissions(10L, SYSTEM)).thenReturn(List.of("CV", "CE", "MCO", "AV"));

        Map<String, Object> me = service.currentUser(auth);
        assertThat(me)
                .containsEntry("subject", "SG000001")
                .containsEntry("name", "张老师")
                .containsEntry("no", "SG000001")
                .containsEntry("roles", List.of("teacher"))
                .containsEntry("permissions", List.of("CV", "CE", "MCO", "AV"));

        assertThat(service.checkPermission(auth, "MCO")).containsEntry("allowed", true);
        assertThat(service.checkPermission(auth, "MTR")).containsEntry("allowed", false);

        assertThat(service.checkApiPermission(auth, "createCourse"))
                .containsEntry("operationId", "createCourse").containsEntry("allowed", true);
        assertThat(service.checkApiPermission(auth, "reviewCourse"))
                .containsEntry("operationId", "reviewCourse").containsEntry("allowed", false);
        assertThat(service.checkApiPermission(auth, "listAuditLogs"))
                .containsEntry("operationId", "listAuditLogs").containsEntry("allowed", true);
        assertThatThrownBy(() -> service.checkApiPermission(auth, "unknownOperation"))
                .isInstanceOf(ApiException.class)
                .extracting("status").isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    @DisplayName("R24 统一身份部门树、部门用户与用户资料查询严格校验 ORG_VIEW/TEC 权限及 404 边界")
    void organizationAndUserLookupEnforcePermissionsAndReturnNotFound() {
        String token = tokenService.issue("SG000001", List.of(SYSTEM), Instant.now());
        String auth = "Bearer " + token;
        when(identityDao.activeSession(eq(Credentials.hash(token)), any())).thenReturn(true);
        when(identityDao.userByExternalId("SG000001"))
                .thenReturn(Optional.of(new IdentityDao.UserRow(10L, "SG000001", "张老师")));

        // 缺少 ORG_VIEW 且非 admin 返回 403
        when(identityDao.permissions(10L, SYSTEM)).thenReturn(List.of("CV"));
        when(identityDao.roles(10L, SYSTEM)).thenReturn(List.of("student"));
        assertThatThrownBy(() -> service.departments(auth, null, null, 1, 20))
                .isInstanceOf(ApiException.class)
                .extracting("status").isEqualTo(HttpStatus.FORBIDDEN);

        // 具备 ORG_VIEW 可查部门树和部门用户，不存在的部门返回 404
        when(identityDao.permissions(10L, SYSTEM)).thenReturn(List.of("ORG_VIEW", "TEC"));
        when(identityDao.departments(null, null, 1, 20))
                .thenReturn(List.of(new IdentityDao.DepartmentRow(1L, "course", "课程部", null, true)));
        when(identityDao.departmentCount(null, null)).thenReturn(1L);
        Map<String, Object> depts = service.departments(auth, null, null, 1, 20);
        assertThat(depts).containsEntry("total", 1L);

        when(identityDao.departmentExists(1L)).thenReturn(true);
        when(identityDao.departmentUsers(1L, null, 1, 20))
                .thenReturn(List.of(new IdentityDao.DepartmentUserRow("SG000001", "SG000001", "张老师", 1L, "课程部")));
        when(identityDao.departmentUserCount(1L, null)).thenReturn(1L);
        assertThat(service.departmentUsers(auth, 1L, null, 1, 20)).containsEntry("total", 1L);

        when(identityDao.departmentExists(999L)).thenReturn(false);
        assertThatThrownBy(() -> service.departmentUsers(auth, 999L, null, 1, 20))
                .isInstanceOf(ApiException.class)
                .extracting("status").isEqualTo(HttpStatus.NOT_FOUND);

        // 具备 TEC 权限查询外部用户，不存在返回 404
        when(identityDao.userByExternalId("T2001"))
                .thenReturn(Optional.of(new IdentityDao.UserRow(20L, "T2001", "李教授")));
        assertThat(service.lookupUser(auth, "T2001"))
                .containsEntry("userId", "T2001").containsEntry("no", "T2001").containsEntry("name", "李教授");

        when(identityDao.userByExternalId("MISSING")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.lookupUser(auth, "MISSING"))
                .isInstanceOf(ApiException.class)
                .extracting("status").isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    @DisplayName("R25 课程审计日志查询无 AV 权限返 403，并对已删除操作人保留历史标识与 deleted 标记")
    void auditLogsForbidUnauthorizedUserAndMarkDeletedActors() {
        String token = tokenService.issue("SG000001", List.of(SYSTEM), Instant.now());
        String auth = "Bearer " + token;
        when(identityDao.activeSession(eq(Credentials.hash(token)), any())).thenReturn(true);
        when(identityDao.userByExternalId("SG000001"))
                .thenReturn(Optional.of(new IdentityDao.UserRow(10L, "SG000001", "张老师")));

        when(identityDao.permissionDepartments(10L, SYSTEM, "AV")).thenReturn(List.of());
        assertThatThrownBy(() -> service.auditLogs(auth, null, null, null, null, null, 1, 20))
                .isInstanceOf(ApiException.class)
                .extracting("status").isEqualTo(HttpStatus.FORBIDDEN);

        when(identityDao.permissionDepartments(10L, SYSTEM, "AV")).thenReturn(List.of(1L));
        Map<String, Object> deletedActorRow = new LinkedHashMap<>();
        deletedActorRow.put("id", 99L);
        deletedActorRow.put("at", Timestamp.from(Instant.parse("2026-11-20T08:00:00Z")));
        deletedActorRow.put("type", "score_changed");
        deletedActorRow.put("target", "课程甲");
        deletedActorRow.put("actorNo", "OLD_TEACHER");
        deletedActorRow.put("actorId", null);
        deletedActorRow.put("actorName", null);
        when(identityDao.courseAuditEvents(SYSTEM, List.of(1L), null, null, null, null, null, 1, 20))
                .thenReturn(new RbacDao.Page(List.of(deletedActorRow), 1L));
        when(identityDao.auditActorRoles(List.of(), SYSTEM, List.of(1L))).thenReturn(Map.of());

        Map<String, Object> page = service.auditLogs(auth, null, null, null, null, null, 1, 20);
        assertThat(page).containsEntry("total", 1L);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) page.get("items");
        @SuppressWarnings("unchecked")
        Map<String, Object> actor = (Map<String, Object>) items.get(0).get("actor");
        assertThat(actor)
                .containsEntry("id", null)
                .containsEntry("name", "OLD_TEACHER")
                .containsEntry("roles", List.of())
                .containsEntry("deleted", true);
    }
}
