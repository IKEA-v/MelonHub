package com.melonhub.rbac.requirements.d_governance;

import static org.assertj.core.api.Assertions.*;

import com.melonhub.rbac.dao.Visibility;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.requirements.support.GovernanceIntegrationSupport;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R13（见 doc/requirements.md）。 */
class R13_AccessReviewIntegrationTest extends GovernanceIntegrationSupport {

    @DisplayName("R13 关闭定期权限复核执行标记回收项")
    @Test @SuppressWarnings("unchecked") void closingReviewAppliesRevokeDecisions() {
        r.userRoles(u2, d1, a1, List.of(r2), ACTOR);
        String token = issue();
        var review = g.createReview(new Requests.ReviewCreate("三季度复核", a1, d1, 7), "admin");
        long reviewId = requestId(review);
        assertThat(((Number) review.get("items")).longValue()).isEqualTo(2);
        var items = (List<Map<String, Object>>) g.reviewItems(reviewId, null, 1, 50).get("items");
        long keepItem = -1, revokeItem = -1;
        for (var item : items) {
            if (((Number) item.get("userId")).longValue() == u1) revokeItem = requestId(item);
            else keepItem = requestId(item);
        }
        final long revoke = revokeItem, keep = keepItem;
        g.decideReviewItem(reviewId, revoke, new Requests.ReviewItemDecision("REVOKE", "不再需要"), "admin");
        g.decideReviewItem(reviewId, keep, new Requests.ReviewItemDecision("REVOKE", null), "admin");
        // A reviewer can change their mind until the review is closed.
        g.decideReviewItem(reviewId, keep, new Requests.ReviewItemDecision("KEEP", "仍在使用"), "admin");
        var kept = (List<Map<String, Object>>) g.reviewItems(reviewId, "KEEP", 1, 50).get("items");
        assertThat(kept).singleElement().satisfies(item -> assertThat(item.get("comment")).isEqualTo("仍在使用"));
        var closed = g.closeReview(reviewId, "admin");
        assertThat(closed.get("status")).isEqualTo("CLOSED");
        assertThat(closed.get("summary").toString()).contains("回收 1 条");
        assertThat(r.assignments(u1, d1, a1).get("roleIds")).isEqualTo(List.of());
        assertThat(r.assignments(u2, d1, a1).get("roleIds")).isEqualTo(List.of(r2));
        assertThatThrownBy(() -> c.effective(a1, token)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> g.decideReviewItem(reviewId, keep, new Requests.ReviewItemDecision("REVOKE", null), "admin"))
                .isInstanceOf(ApiException.class).hasMessageContaining("已关闭");
    }

    @DisplayName("R13 关闭复核仅回收快照对应 grant_id 跳过续期新授权")
    @Test @SuppressWarnings("unchecked") void closingReviewOnlyRevokesTheGrantItSnapshotted() {
        r.userRoles(u2, d1, a1, List.of(r2), ACTOR);
        long reviewId = requestId(g.createReview(new Requests.ReviewCreate("变更跳过", a1, d1, 7), "admin"));
        for (var item : (List<Map<String, Object>>) g.reviewItems(reviewId, null, 1, 50).get("items"))
            g.decideReviewItem(reviewId, requestId(item), new Requests.ReviewItemDecision("REVOKE", null), "admin");
        // Removed and granted again after the snapshot: a newer decision the reviewer never saw.
        r.userRoles(u1, d1, a1, List.of(), ACTOR);
        r.userRoles(u1, d1, a1, List.of(r1), ACTOR);
        var closed = g.closeReview(reviewId, "admin");
        assertThat(closed.get("summary").toString()).contains("回收 1 条").contains("1 条在复核期间已变更");
        assertThat(((Number) closed.get("skipped")).intValue()).isEqualTo(1);
        assertThat(r.assignments(u1, d1, a1).get("roleIds")).isEqualTo(List.of(r1));
        assertThat(r.assignments(u2, d1, a1).get("roleIds")).isEqualTo(List.of());
    }

    @DisplayName("R13 删除用户或角色后申请与复核历史快照仍保留")
    @Test @SuppressWarnings("unchecked") void governanceHistorySurvivesDeletingTheUserOrRole() {
        long approved = requestId(g.submit(a1, new Requests.AccessRequestSubmit(external, d1, r2, "需要写权限", null), "app:" + a1));
        g.approve(approved, new Requests.RequestApprove(null, "同意"), "admin");
        long pending = requestId(g.submit(a1, new Requests.AccessRequestSubmit(external2, d1, r2, "也需要", null), "app:" + a1));
        long reviewId = requestId(g.createReview(new Requests.ReviewCreate("删除前快照", a1, d1, 7), "admin"));
        r.deleteRole(r2, d1, a1, ACTOR);
        var cancelled = g.request(pending);
        assertThat(cancelled.get("status")).isEqualTo("CANCELLED");
        assertThat(cancelled.get("roleId")).isNull();
        assertThat(cancelled.get("roleCode")).isEqualTo("writer");
        r.deleteUser(u1, ACTOR, null);
        var history = g.request(approved);
        assertThat(history.get("status")).isEqualTo("APPROVED");
        assertThat(history.get("userId")).isNull();
        assertThat(history.get("externalId")).isEqualTo(external);
        assertThat(history.get("userName")).isEqualTo("GovUser");
        assertThat(history.get("roleName")).isEqualTo("Writer");
        assertThat(((Number) g.requests(a1, Visibility.ALL, null, external, 1, 20).get("total")).intValue()).isEqualTo(2);
        var items = (List<Map<String, Object>>) g.reviewItems(reviewId, null, 1, 50).get("items");
        assertThat(items).hasSize(2).allSatisfy(item -> assertThat(item.get("externalId")).isEqualTo(external));
        for (var item : items) g.decideReviewItem(reviewId, requestId(item), new Requests.ReviewItemDecision("REVOKE", null), "admin");
        assertThat(((Number) g.closeReview(reviewId, "admin").get("skipped")).intValue()).isEqualTo(2);
    }
}
