package com.melonhub.rbac.requirements.d_governance;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.requirements.support.GovernanceIntegrationSupport;
import com.melonhub.rbac.security.Credentials;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

/** 对应需求：R12（见 doc/requirements.md）。 */
class R12_AccessRequestApprovalIntegrationTest extends GovernanceIntegrationSupport {

    @DisplayName("R12 角色申请批准后立即授角并在到期后失效")
    @Test @SuppressWarnings("unchecked") void approvedRequestGrantsRoleUntilItsExpiry() throws Exception {
        var submitted = g.submit(a1, new Requests.AccessRequestSubmit(external, d1, r2, "月末报表需要写权限", 30), "app:" + a1);
        assertThat(submitted.get("status")).isEqualTo("PENDING");
        assertThatThrownBy(() -> g.submit(a1, new Requests.AccessRequestSubmit(external, d1, r2, "重复", null), "app:" + a1))
                .isInstanceOf(ApiException.class).hasMessageContaining("待审批");
        long id = requestId(submitted);
        var approved = g.approve(id, new Requests.RequestApprove(null, "同意"), "admin");
        assertThat(approved.get("status")).isEqualTo("APPROVED");
        assertThat(approved.get("grantExpiresAt")).isNotNull();
        assertThatThrownBy(() -> g.approve(id, new Requests.RequestApprove(null, null), "admin"))
                .isInstanceOf(ApiException.class).hasMessageContaining("已被处理");
        assertThat(c.effective(a1, issue()).get("permissions")).isEqualTo(List.of("item:read", "item:write"));
        // Once the assignment lapses, the next context no longer contains it.
        db.update("UPDATE user_roles SET expires_at=TIMESTAMPADD(SECOND,-10,CURRENT_TIMESTAMP) WHERE user_id=? AND role_id=?", u1, r2);
        assertThat(c.effective(a1, issue()).get("permissions")).isEqualTo(List.of("item:read"));
        assertThat((List<Object>) g.myAccess(a1, external, d1).get("permissions")).containsExactly("item:read");
    }

    @DisplayName("R12 角色申请驳回与员工撤销流程正确")
    @Test void rejectionAndEmployeeCancellation() throws Exception {
        long hook = ((Number) webhooks.create(a1, new Requests.Webhook("驳回通知", "http://127.0.0.1:1/hook", null, List.of("access.rejected"), true), ACTOR)
                .get("id")).longValue();
        var rejected = g.reject(requestId(g.submit(a1, new Requests.AccessRequestSubmit(external, d1, r2, "需要", null), "app:" + a1)),
                new Requests.RequestReject("权限过大"), "admin");
        assertThat(rejected.get("status")).isEqualTo("REJECTED");
        assertThat(rejected.get("decisionComment")).isEqualTo("权限过大");
        // The business system can show the reason without asking the console.
        String payload = db.queryForObject("SELECT payload FROM webhook_deliveries WHERE webhook_id=?", String.class, hook);
        assertThat(mapper.readTree(payload).path("data").path("comment").asText()).isEqualTo("权限过大");
        var again = g.submit(a1, new Requests.AccessRequestSubmit(external, d1, r2, "再次申请", null), "app:" + a1);
        assertThatThrownBy(() -> g.cancelOwn(a1, requestId(again), external2, "app:" + a1)).isInstanceOf(ApiException.class);
        g.cancelOwn(a1, requestId(again), external, "app:" + a1);
        assertThat(g.request(requestId(again)).get("status")).isEqualTo("CANCELLED");
        assertThat(g.myRequests(a1, external)).hasSize(2);
    }

    @DisplayName("R12 查询本人申请先按软件过滤再限条数")
    @Test void ownRequestsAreFilteredByApplicationBeforeTheyAreLimited() {
        var other = r.application(new Requests.Application("Gov Other", "go-" + Credentials.token().substring(0, 12), ""), ACTOR);
        long a2 = ((Number) other.get("id")).longValue();
        long otherRole = r.role(new Requests.Role("Other", "other", ""), null, d1, a2, ACTOR);
        long mine = requestId(g.submit(a1, new Requests.AccessRequestSubmit(external, d1, r2, "本软件的申请", null), "app:" + a1));
        for (int i = 0; i < 60; i++)
            db.update("INSERT INTO access_requests(user_id,department_id,application_id,role_id,reason,status,requested_by) VALUES (?,?,?,?,?,'CANCELLED',?)",
                    u1, d1, a2, otherRole, "其他软件 " + i, "app:" + a2);
        assertThat(g.myRequests(a1, external)).extracting(row -> ((Number) row.get("id")).longValue()).containsExactly(mine);
        assertThat(g.myRequests(a2, external)).hasSize(50);
    }

    @DisplayName("R12 治理接口全部受管理功能与范围保护")
    @Test void governanceEndpointsAreExposedAndGuarded() throws Exception {
        mvc.perform(get("/api/admin/access-requests")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/access-requests")
                        .header("X-API-Key", key1)
                        .contentType("application/json")
                        .content(mapper.writeValueAsString(Map.of("externalId", external2, "departmentId", d1, "roleId", r2, "reason", "联调"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PENDING"));
        mvc.perform(get("/api/v1/access-requests").header("X-API-Key", key1).param("externalId", external2))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].status").value("PENDING"));
        mvc.perform(get("/api/v1/users/access").header("X-API-Key", key1).param("externalId", external2).param("departmentId", String.valueOf(d1)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permissions").isArray());
        mvc.perform(get("/api/admin/system/status")).andExpect(status().isUnauthorized());
    }

    @DisplayName("R12 同一用户对同一角色同时仅保留一条待审批申请")
    @Test void theDatabaseKeepsOnePendingRequestPerUserAndRole() {
        g.submit(a1, new Requests.AccessRequestSubmit(external, d1, r2, "第一次", null), "app:" + a1);
        assertThatThrownBy(() -> db.update("INSERT INTO access_requests(user_id,department_id,application_id,role_id,pending_role_id,reason,status,requested_by) "
                + "VALUES (?,?,?,?,?,'并发提交','PENDING','test')", u1, d1, a1, r2, r2)).isInstanceOf(DataIntegrityViolationException.class);
    }

    @DisplayName("R12 审批通过时可改授永久或自定义有效天数")
    @Test void approverCanGrantPermanentlyOrForAnotherDuration() {
        long first = requestId(g.submit(a1, new Requests.AccessRequestSubmit(external, d1, r2, "申请 30 天", 30), "app:" + a1));
        assertThatThrownBy(() -> g.approve(first, new Requests.RequestApprove(7, null, true), "admin")).isInstanceOf(ApiException.class);
        var approved = g.approve(first, new Requests.RequestApprove(null, "长期需要", true), "admin");
        assertThat(approved.get("grantExpiresAt")).isNull();
        assertThat(expiresAt(u1, r2)).isNull();
        long second = requestId(g.submit(a1, new Requests.AccessRequestSubmit(external2, d1, r2, "申请永久", null), "app:" + a1));
        g.approve(second, new Requests.RequestApprove(7, null, false), "admin");
        assertThat(expiresAt(u2, r2)).isBetween(Instant.now().plus(6, ChronoUnit.DAYS), Instant.now().plus(8, ChronoUnit.DAYS));
    }
}
