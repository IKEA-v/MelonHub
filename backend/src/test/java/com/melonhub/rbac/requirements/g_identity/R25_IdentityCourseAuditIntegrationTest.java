package com.melonhub.rbac.requirements.g_identity;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.melonhub.rbac.CloudTestDatabaseGuard;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.identity.IdentityService;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.service.RbacService;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

/** 验证课程管理员日志的分页契约及授权域隔离。 对应需求：R25（见 doc/requirements.md）。 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ContextConfiguration(initializers = CloudTestDatabaseGuard.class)
@Transactional
class R25_IdentityCourseAuditIntegrationTest {
    private static final String SYSTEM = "course-project-management";
    private static final String AUDIT_PATH = "/auth/audit-logs";
    private static final String TEST_PASSWORD = "fixture-only-identity-password";

    @Autowired MockMvc mvc;
    @Autowired RbacService rbac;
    @Autowired IdentityService identity;

    @Test
    @DisplayName("R25 GET /auth/audit-logs 仅返回持有 AV 权限部门内的课程业务日志")
    void queriesOnlyCourseBusinessEventsInAuthorizedDepartments() throws Exception {
        String suffix = Credentials.token().substring(0, 12);
        String username = "audit-" + suffix;
        long department = rbac.department(new Requests.Department("课程部门", "audit-dept-" + suffix), null, "test");
        long otherDepartment = rbac.department(new Requests.Department("其他部门", "audit-other-" + suffix), null, "test");
        long app = application(SYSTEM);
        long otherApp = application("audit-app-" + suffix);
        long admin = rbac.role(new Requests.Role("课程管理员", "admin", ""), null, department, app, "test");
        long permission = rbac.permission(new Requests.Permission("查看课程日志", "AV", "audit", "view"),
                null, department, app, "test");
        rbac.rolePermissions(admin, department, app, List.of(permission), "test");
        long user = identity.provisionUser(new Requests.User("审计测试教师", username, "", List.of(department, otherDepartment)),
                TEST_PASSWORD, "test");
        rbac.userRoles(user, department, app, List.of(admin), "test");

        rbac.audit(username, "score_changed", "课程日志甲", department, app);
        rbac.audit(username, "group_changed", "课程日志乙", department, app);
        rbac.audit(username, "USER_ROLES_UPDATED", "课程日志平台授权", department, app);
        rbac.audit(username, "roster_changed", "课程日志其他部门", otherDepartment, app);
        rbac.audit(username, "milestone_changed", "课程日志其他软件", department, otherApp);
        String token = "Bearer " + identity.login(username, TEST_PASSWORD, List.of(SYSTEM)).get("accessToken");

        mvc.perform(get("/auth/api-permissions/listAuditLogs").header("Authorization", token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.allowed").value(true));
        mvc.perform(get(AUDIT_PATH).header("Authorization", token).param("pageSize", "1")
                        .param("actorId", Long.toString(user)).param("actor", "审计测试")
                        .param("target", "课程日志"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.pageSize").value(1)).andExpect(jsonPath("$.total").value(2))
                .andExpect(jsonPath("$.items[0].target").value("课程日志乙"))
                .andExpect(jsonPath("$.items[0].type").value("group_changed"))
                .andExpect(jsonPath("$.items[0].at").isString())
                .andExpect(jsonPath("$.items[0].actor.id").value(user))
                .andExpect(jsonPath("$.items[0].actor.roles[0]").value("admin"));
        mvc.perform(get(AUDIT_PATH).header("Authorization", token).param("target", "没有匹配的日志"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.total").value(0))
                .andExpect(jsonPath("$.items").isEmpty());
        mvc.perform(get(AUDIT_PATH).header("Authorization", token).param("page", "0"))
                .andExpect(status().isBadRequest());
        rbac.rolePermissions(admin, department, app, List.of(), "test");
        mvc.perform(get(AUDIT_PATH).header("Authorization", token)).andExpect(status().isForbidden());
        mvc.perform(get(AUDIT_PATH)).andExpect(status().isUnauthorized());
    }

    private long application(String code) {
        return ((Number) rbac.application(new Requests.Application("审计测试软件", code, ""), "test").get("id")).longValue();
    }
}
