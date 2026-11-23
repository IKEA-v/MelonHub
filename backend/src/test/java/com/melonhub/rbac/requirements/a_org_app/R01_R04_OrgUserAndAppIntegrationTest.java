package com.melonhub.rbac.requirements.a_org_app;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.requirements.support.RbacIntegrationSupport;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/** 对应需求：R1、R2、R3、R4（见 doc/requirements.md）。 */
class R01_R04_OrgUserAndAppIntegrationTest extends RbacIntegrationSupport {

    @DisplayName("R2 停用用户旧上下文失效且重新启用不恢复")
    @Test void disabledUserCannotReuseOldContextAfterReactivation() {
        String token = issue(a1, d1);
        r.userStatus(u1, false, "test");
        assertThatThrownBy(() -> c.effective(a1, token)).isInstanceOf(ApiException.class);
        r.userStatus(u1, true, "test");
        assertThatThrownBy(() -> c.effective(a1, token)).isInstanceOf(ApiException.class);
    }

    @DisplayName("R2 修改姓名邮箱保留上下文但修改外部标识立即失效上下文")
    @Test void editingDisplayFieldsKeepsContextsButChangingExternalIdEndsThem() {
        String token = issue(a1, d1);
        r.user(new Requests.User("Renamed", external, "renamed@example.com", List.of(d1, d2)), u1, "test");
        assertThat(c.effective(a1, token).get("permissions")).isEqualTo(List.of("item:read", "item:write"));
        r.user(new Requests.User("Renamed", external + "-moved", "", List.of(d1, d2)), u1, "test");
        assertThatThrownBy(() -> c.effective(a1, token)).isInstanceOf(ApiException.class);
    }

    @DisplayName("R2 移出部门成员关系清除该部门授权与上下文")
    @Test void removingMembershipEndsContextsInThatDepartment() {
        String token = issue(a1, d1);
        r.user(new Requests.User("User", external, "", List.of(d2)), u1, "test");
        assertThatThrownBy(() -> c.effective(a1, token)).isInstanceOf(ApiException.class);
        assertThat(r.assignments(u1, d1, a1).get("roleIds")).isEqualTo(List.of());
    }

    @DisplayName("R1/R3 删除有依赖的部门或软件返回 409 并列出剩余数量")
    @Test void deletingDepartmentOrApplicationInUseNamesWhatRemains() {
        assertThatThrownBy(() -> r.deleteDepartment(d2, "test")).isInstanceOf(ApiException.class)
                .hasMessageContaining("1 名成员").hasMessageContaining("1 个角色").hasMessageContaining("1 个权限");
        assertThatThrownBy(() -> r.deleteApplication(a2, "test")).isInstanceOf(ApiException.class)
                .hasMessageContaining("1 个角色").hasMessageContaining("1 个权限");
        issue(a1, d2);
        r.user(new Requests.User("User", external, "", List.of(d1)), u1, "test");
        r.deleteRole(rOther, d2, a1, "test");
        r.deletePermission(pOther, d2, a1, "test");
        r.deleteDepartment(d2, "test");
        assertThat(db.queryForObject("SELECT COUNT(*) FROM departments WHERE id=?", Long.class, d2)).isZero();
        assertThat(db.queryForObject("SELECT target FROM audit_events WHERE action='DEPARTMENT_DELETED' ORDER BY id DESC LIMIT 1", String.class)).isEqualTo("Second");
        r.deleteRole(rOtherApp, d1, a2, "test");
        r.deletePermission(pOtherApp, d1, a2, "test");
        r.deleteApplication(a2, "test");
        assertThat(db.queryForObject("SELECT COUNT(*) FROM applications WHERE id=?", Long.class, a2)).isZero();
        assertThat(db.queryForObject("SELECT target FROM audit_events WHERE action='APPLICATION_DELETED' ORDER BY id DESC LIMIT 1", String.class)).isEqualTo("Two");
    }

    @DisplayName("R2 强制下线撤销用户全部上下文")
    @Test void forcedSignOutEndsEveryContextOfTheUser() {
        String one = issue(a1, d1), two = issue(a2, d1);
        assertThat(r.revokeUserContexts(u1, "test", null)).isEqualTo(2);
        assertThatThrownBy(() -> c.effective(a1, one)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> c.effective(a2, two)).isInstanceOf(ApiException.class);
        assertThat(c.effective(a1, issue(a1, d1)).get("permissions")).isEqualTo(List.of("item:read", "item:write"));
    }

    @DisplayName("R2 用户列表支持分页、关键词及筛选检索")
    @Test void usersArePagedAndSearchable() {
        var page = r.users(external, null, null, null, 1, 1);
        assertThat(page.get("total")).isEqualTo(2L);
        assertThat((List<?>) page.get("items")).hasSize(1);
        assertThat(((Map<?, ?>) ((List<?>) page.get("items")).get(0)).get("departmentIds")).isEqualTo(List.of(d1, d2));
        assertThat(r.users(external, d2, null, null, 1, 20).get("total")).isEqualTo(1L);
        assertThat(r.users("%", null, null, null, 1, 20).get("total")).isEqualTo(0L);
        var assignments = r.domainAssignments(d1, a1, external, 1, 20);
        assertThat(assignments.get("total")).isEqualTo(2L);
    }

    @DisplayName("R4 API Key 绑定所属软件不可操作异软件角色")
    @Test void apiKeyIsBoundToApplicationAndCannotAssignForeignRoles() throws Exception {
        mvc.perform(get("/api/v1/departments/" + d1 + "/roles").param("applicationId", String.valueOf(a2)).header("X-API-Key", key1))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(2));
        mvc.perform(put("/api/v1/departments/" + d1 + "/users/" + u1 + "/roles").header("X-API-Key", key1)
                        .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of("ids", List.of(rOtherApp)))))
                .andExpect(status().isForbidden());
        String token = issue(a1, d1);
        mvc.perform(get("/api/v1/contexts/effective").header("X-API-Key", key2).header("X-Context-Token", token))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("CONTEXT_INVALID"));
    }

    @DisplayName("R4 控制台凭证与业务 API Key 严格隔离不可混用")
    @Test void adminAndBusinessEndpointsRequireDistinctCredentials() throws Exception {
        mvc.perform(get("/api/admin/users")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/admin/users").header("X-API-Key", key1)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/departments").header("Authorization", "Bearer fake")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/departments").header("X-API-Key", key1)).andExpect(status().isOk());
    }

    @DisplayName("R4 紧急轮换密钥后旧密钥立即失效")
    @Test void keyRotationRejectsOldKeyImmediately() throws Exception {
        String fresh = r.rotateKey(a1, "test");
        mvc.perform(get("/api/v1/departments").header("X-API-Key", key1)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/departments").header("X-API-Key", fresh)).andExpect(status().isOk());
    }

    @DisplayName("R4 单软件支持多密钥独立有效期与吊销")
    @Test void applicationsCanHoldSeveralKeysWithExpiryAndRevocation() throws Exception {
        var second = r.createKey(a1, new Requests.ApiKey("second", 30), "test");
        String key = (String) second.get("apiKey");
        mvc.perform(get("/api/v1/departments").header("X-API-Key", key)).andExpect(status().isOk());
        mvc.perform(get("/api/v1/departments").header("X-API-Key", key1)).andExpect(status().isOk());
        long first = ((Number) r.keys(a1).stream().filter(k -> "默认密钥".equals(k.get("name"))).findFirst().orElseThrow().get("id")).longValue();
        r.revokeKey(a1, first, "test");
        assertThatThrownBy(() -> r.revokeKey(a1, first, "test")).isInstanceOf(ApiException.class);
        mvc.perform(get("/api/v1/departments").header("X-API-Key", key1)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/departments").header("X-API-Key", key)).andExpect(status().isOk());
        assertThat(r.keys(a1)).extracting(k -> k.get("status")).containsExactly("ACTIVE", "REVOKED");
        db.update("UPDATE application_keys SET expires_at=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 1 SECOND) WHERE id=?", second.get("id"));
        mvc.perform(get("/api/v1/departments").header("X-API-Key", key)).andExpect(status().isUnauthorized());
    }

    @DisplayName("R3 停用软件后其密钥与上下文全部失效")
    @Test void disabledApplicationLosesKeysAndContexts() throws Exception {
        String token = issue(a1, d1);
        r.applicationStatus(a1, false, "test");
        mvc.perform(get("/api/v1/departments").header("X-API-Key", key1)).andExpect(status().isUnauthorized());
        assertThatThrownBy(() -> c.effective(a1, token)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> c.issue(a1, new Requests.Context(external, d1, null), "test")).isInstanceOf(ApiException.class);
    }
}
