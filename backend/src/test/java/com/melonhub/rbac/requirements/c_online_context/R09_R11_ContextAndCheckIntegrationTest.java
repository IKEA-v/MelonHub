package com.melonhub.rbac.requirements.c_online_context;

import static org.assertj.core.api.Assertions.*;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.requirements.support.RbacIntegrationSupport;
import com.melonhub.rbac.security.Credentials;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R9、R10、R11（见 doc/requirements.md）。 */
class R09_R11_ContextAndCheckIntegrationTest extends RbacIntegrationSupport {

    @DisplayName("R10 应用时钟与数据库到期判断口径一致")
    @Test void timestampsAndDatabaseExpiryUseTheSameClock() {
        Instant created = db.queryForObject("SELECT created_at FROM departments WHERE id=?", Timestamp.class, d1).toInstant();
        assertThat(created).isAfter(Instant.now().minusSeconds(30)).isBefore(Instant.now().plusSeconds(5));
        String context = issue(a1, d1);
        assertThat(db.queryForObject("SELECT TIMESTAMPDIFF(SECOND,CURRENT_TIMESTAMP,expires_at) FROM permission_contexts WHERE id=?", Long.class, Credentials.hash(context))).isBetween(3570L, 3600L);
        String session = Credentials.hash(Credentials.token());
        authDao.createSession(session, authDao.account(adminUser).orElseThrow(), Instant.now().truncatedTo(ChronoUnit.SECONDS).plusSeconds(28800), "127.0.0.1");
        assertThat(db.queryForObject("SELECT TIMESTAMPDIFF(SECOND,CURRENT_TIMESTAMP,expires_at) FROM admin_sessions WHERE token_hash=?", Long.class, session)).isBetween(28770L, 28800L);
    }

    @DisplayName("R10 有效权限严格为已分配启用角色权限的并集")
    @Test void effectivePermissionsAreUnionOfAssignedRolesOnly() {
        String token = issue(a1, d1);
        assertThat(c.effective(a1, token).get("permissions")).isEqualTo(List.of("item:read", "item:write"));
        assertThat(c.check(a1, token, List.of("item:read", "not:assigned")).get("allowed")).isEqualTo(false);
        String noRoles = (String) c.issue(a1, new Requests.Context(external + "-other", d1, null), "test").get("contextToken");
        assertThat((List<?>) c.effective(a1, noRoles).get("permissions")).isEmpty();
    }

    @DisplayName("R9 跨部门切换作废原部门全部软件上下文且切回不恢复")
    @Test void departmentSwitchInvalidatesOldContextsAcrossApplicationsAndSwitchBack() {
        String old = issue(a1, d1), oldOther = issue(a2, d1), next = issue(a1, d2);
        assertThatThrownBy(() -> c.effective(a1, old)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> c.effective(a2, oldOther)).isInstanceOf(ApiException.class);
        assertThat(c.effective(a1, next).get("permissions")).isEqualTo(List.of("item:read"));
        issue(a1, d1);
        assertThatThrownBy(() -> c.effective(a1, next)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> c.effective(a1, old)).isInstanceOf(ApiException.class);
    }

    @DisplayName("R9 同一部门下不同软件的上下文可共存")
    @Test void sameDepartmentInDifferentApplicationsKeepsBothContextsValid() {
        String one = issue(a1, d1), two = issue(a2, d1);
        assertThat(c.effective(a1, one).get("permissions")).isEqualTo(List.of("item:read", "item:write"));
        assertThat(c.effective(a2, two).get("permissions")).isEqualTo(List.of("item:read"));
    }

    @DisplayName("R9 上下文激活角色必须是已分配角色的子集")
    @Test void activeRolesMustBeAssignedSubset() {
        String token = (String) c.issue(a1, new Requests.Context(external, d1, List.of(r1)), "test").get("contextToken");
        assertThat(c.effective(a1, token).get("permissions")).isEqualTo(List.of("item:read"));
        assertThatThrownBy(() -> c.issue(a1, new Requests.Context(external, d1, List.of(rOtherApp)), "test")).isInstanceOf(ApiException.class);
        String empty = (String) c.issue(a1, new Requests.Context(external, d1, List.of()), "test").get("contextToken");
        assertThat((List<?>) c.effective(a1, empty).get("permissions")).isEmpty();
    }

    @DisplayName("R9 非部门成员禁止切换到该部门")
    @Test void nonmemberCannotSwitchDepartments() {
        assertThatThrownBy(() -> c.issue(a1, new Requests.Context(external + "-other", d2, null), "test")).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> r.userRoles(u2, d2, a1, List.of(rOther), "test")).isInstanceOf(ApiException.class);
    }

    @DisplayName("R10 已过期或已撤销上下文被拒绝")
    @Test void expiredAndRevokedContextsAreRejected() {
        String token = issue(a1, d1);
        db.update("UPDATE permission_contexts SET expires_at=DATE_SUB(CURRENT_TIMESTAMP,INTERVAL 1 SECOND) WHERE id=?", Credentials.hash(token));
        assertThatThrownBy(() -> c.effective(a1, token)).isInstanceOf(ApiException.class);
        String fresh = issue(a1, d1);
        c.revoke(a1, fresh, "test");
        assertThatThrownBy(() -> c.effective(a1, fresh)).isInstanceOf(ApiException.class);
    }

    @DisplayName("R11 权限诊断不切换用户部门并解释授权依据")
    @Test void simulationExplainsAccessWithoutSwitchingDepartments() {
        String token = issue(a1, d1);
        var result = r.simulate(new Requests.Simulation(u1, d2, a1, null, List.of("item:read", "item:write")));
        assertThat(result.get("eligible")).isEqualTo(true);
        assertThat(result.get("switchesDepartment")).isEqualTo(true);
        assertThat(result.get("decisions")).isEqualTo(Map.of("item:read", true, "item:write", false));
        assertThat(c.effective(a1, token).get("permissions")).isEqualTo(List.of("item:read", "item:write"));
        assertThat(db.queryForObject("SELECT active_department_id FROM users WHERE id=?", Long.class, u1)).isEqualTo(d1);
        var outsider = r.simulate(new Requests.Simulation(u2, d2, a1, null, List.of("item:read")));
        assertThat(outsider.get("eligible")).isEqualTo(false);
        assertThat(outsider.get("allowed")).isEqualTo(false);
        var foreignRole = r.simulate(new Requests.Simulation(u1, d1, a1, List.of(rOtherApp), null));
        assertThat(foreignRole.get("eligible")).isEqualTo(false);
    }
}
