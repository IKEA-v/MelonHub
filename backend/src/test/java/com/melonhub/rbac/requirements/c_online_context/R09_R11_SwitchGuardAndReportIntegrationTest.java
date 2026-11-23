package com.melonhub.rbac.requirements.c_online_context;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.melonhub.rbac.dao.Visibility;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.requirements.support.GovernanceIntegrationSupport;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R9、R11（见 doc/requirements.md）。 */
class R09_R11_SwitchGuardAndReportIntegrationTest extends GovernanceIntegrationSupport {

    @DisplayName("R9 创建上下文设 switchDepartment=false 时拒绝隐式切部门返回 409")
    @Test void contextCreationCanRefuseToSwitchTheCurrentDepartment() throws Exception {
        // The very first context has no current department to protect, so it may set one.
        String token = (String) c.issue(a1, new Requests.Context(external, d1, null, false), ACTOR).get("contextToken");
        assertThatThrownBy(() -> c.issue(a1, new Requests.Context(external, d2, null, false), ACTOR))
                .isInstanceOf(ApiException.class).extracting("code").isEqualTo("DEPARTMENT_MISMATCH");
        mvc.perform(post("/api/v1/contexts").header("X-API-Key", key1).contentType("application/json")
                        .content(mapper.writeValueAsString(Map.of("externalId", external, "departmentId", d2, "switchDepartment", false))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("DEPARTMENT_MISMATCH"));
        c.issue(a1, new Requests.Context(external, d1, null, false), ACTOR);
        assertThat(c.effective(a1, token).get("departmentId")).isEqualTo(d1);
        // Only an explicit switch moves the user and ends the old department's contexts.
        c.issue(a1, new Requests.Context(external, d2, null, true), ACTOR);
        assertThatThrownBy(() -> c.effective(a1, token)).isInstanceOf(ApiException.class);
    }

    @DisplayName("R11 权限诊断报告已到期角色且不阻塞模拟计算")
    @Test @SuppressWarnings("unchecked") void simulationReportsLapsedRolesWithoutBlocking() {
        r.userRoles(u1, d1, a1, List.of(r1, r2), ACTOR);
        db.update("UPDATE user_roles SET expires_at=TIMESTAMPADD(SECOND,-10,CURRENT_TIMESTAMP) WHERE user_id=? AND role_id=?", u1, r2);
        var result = r.simulate(new Requests.Simulation(u1, d1, a1, null, List.of("item:read", "item:write")));
        assertThat(result.get("eligible")).isEqualTo(true);
        assertThat((List<String>) result.get("issues")).isEmpty();
        assertThat((List<String>) result.get("notices")).singleElement().asString().contains("writer");
        assertThat((Map<String, Boolean>) result.get("decisions")).containsEntry("item:read", true).containsEntry("item:write", false);
        // Asking for the lapsed role explicitly would make context creation fail, so that stays a blocking issue.
        var explicit = r.simulate(new Requests.Simulation(u1, d1, a1, List.of(r2), null));
        assertThat(explicit.get("eligible")).isEqualTo(false);
    }

    @DisplayName("R11 权限反查、全局搜索与系统状态查询正常")
    @Test void reverseLookupSearchAndStatus() {
        var holders = g.permissionHolders(a1, "item:read", null, null);
        assertThat(((Number) holders.get("total")).intValue()).isEqualTo(1);
        assertThat(((Number) g.permissionHolders(a1, "item:write", null, null).get("total")).longValue()).isZero();
        assertThat(((Number) g.permissionHolders(a1, "no:such", null, null).get("total")).longValue()).isZero();
        var found = console.search(external, Visibility.ALL);
        assertThat((List<?>) found.get("users")).isNotEmpty();
        assertThat((List<?>) console.search("reader", Visibility.ALL).get("roles")).isNotEmpty();
        var status = console.status(Visibility.ALL);
        assertThat(status.get("database")).isEqualTo("UP");
        assertThat(((Map<?, ?>) status.get("counts")).get("users")).isNotNull();
        assertThat(status.get("audit")).isNotNull();
    }

    @DisplayName("R11 即将到期报表列出临期角色分配")
    @Test void expiringAssignmentsAppearInReport() {
        r.userRoles(u1, d1, a1, List.of(r1), 7, ACTOR);
        assertThat(g.expiringAssignments(30, Visibility.ALL, a1)).anyMatch(row -> ((Number) row.get("userId")).longValue() == u1);
        assertThat(g.expiringAssignments(3, Visibility.ALL, a1)).noneMatch(row -> ((Number) row.get("userId")).longValue() == u1);
        // An expired assignment is excluded from new contexts immediately.
        db.update("UPDATE user_roles SET expires_at=TIMESTAMPADD(SECOND,-5,CURRENT_TIMESTAMP) WHERE user_id=? AND role_id=?", u1, r1);
        assertThat((List<?>) c.effective(a1, issue()).get("permissions")).isEmpty();
    }

    @DisplayName("R11 权限持有者按用户与部门维度去重计数")
    @Test void permissionHoldersAreCountedPerUserAndDepartment() {
        long read = db.queryForObject("SELECT id FROM permissions WHERE department_id=? AND application_id=? AND code='item:read'", Long.class, d1, a1);
        long write = db.queryForObject("SELECT id FROM permissions WHERE department_id=? AND application_id=? AND code='item:write'", Long.class, d1, a1);
        r.rolePermissions(r2, d1, a1, List.of(read, write), ACTOR);
        r.userRoles(u1, d1, a1, List.of(r1, r2), ACTOR);
        r.userRoles(u2, d1, a1, List.of(r2), ACTOR);
        var holders = g.permissionHolders(a1, "item:read", null, null);
        assertThat(((Number) holders.get("total")).longValue()).isEqualTo(2);
        assertThat(holders.get("truncated")).isEqualTo(false);
        assertThat((List<?>) holders.get("holders")).hasSize(2).anySatisfy(holder ->
                assertThat((List<?>) ((Map<?, ?>) holder).get("roles")).hasSize(2));
    }
}
