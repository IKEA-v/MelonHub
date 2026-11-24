package com.melonhub.rbac.service.ddd.infrastructure;

import static com.melonhub.rbac.service.ddd.infrastructure.JpaRbacRepositoryAdapter.toVisibility;
import static com.melonhub.rbac.service.ddd.infrastructure.JpaRbacRepositoryAdapter.ts;

import com.melonhub.rbac.dao.GovernanceDao;
import com.melonhub.rbac.service.ddd.domain.model.AccessRequestAggregate;
import com.melonhub.rbac.service.ddd.domain.model.AccessReviewAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.GovernanceRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.repository.PageSlice;
import com.melonhub.rbac.service.ddd.domain.value.DomainVisibility;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** DDD 基础设施适配器：将 {@link GovernanceRepositoryPort} 桥接到 {@link GovernanceDao}。 */
@Component
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class JpaGovernanceRepositoryAdapter implements GovernanceRepositoryPort {
    private final GovernanceDao dao;

    public JpaGovernanceRepositoryAdapter(GovernanceDao dao) {
        this.dao = dao;
    }

    @Override
    public PageSlice requests(Long applicationId, DomainVisibility visibility, String status, String keyword, int page, int size) {
        var p = dao.requests(applicationId, toVisibility(visibility), status, keyword, page, size);
        return new PageSlice(p.items(), p.total());
    }

    @Override public Optional<Map<String, Object>> requestView(long id) { return dao.request(id); }

    @Override
    public Optional<AccessRequestAggregate> findRequest(long id) {
        return dao.request(id).map(row -> new AccessRequestAggregate(
                number(row.get("id")),
                (String) row.get("status"),
                nullableLong(row.get("userId")),
                nullableLong(row.get("departmentId")),
                number(row.get("applicationId")),
                nullableLong(row.get("roleId")),
                Boolean.TRUE.equals(row.get("roleEnabled")),
                (String) row.get("externalId"),
                (String) row.get("roleCode"),
                row.get("durationDays") == null ? null : ((Number) row.get("durationDays")).intValue()
        ));
    }

    @Override public boolean pendingRequestExists(long userId, long roleId) { return dao.pendingExists(userId, roleId); }
    @Override public long createRequest(long userId, long departmentId, long applicationId, long roleId, String reason, Integer durationDays, String actor) {
        return dao.createRequest(userId, departmentId, applicationId, roleId, reason, durationDays, actor);
    }
    @Override public int decideRequest(long id, String status, String actor, String comment, Instant expiresAt) {
        return dao.decide(id, status, actor, comment, ts(expiresAt));
    }
    @Override public int cancelOwnRequest(long id, long userId) { return dao.cancelOwn(id, userId); }
    @Override public int cancelPendingByColumn(String column, long targetId, String comment) { return dao.cancelPending(column, targetId, comment); }
    @Override public List<Map<String, Object>> requestsOfUser(long userId, long applicationId) { return dao.requestsOfUser(userId, applicationId); }
    @Override public long createReview(String name, long applicationId, Long departmentId, Instant dueAt, String actor) {
        return dao.createReview(name, applicationId, departmentId, ts(dueAt), actor);
    }
    @Override public int insertReviewSnapshot(long reviewId, long applicationId, Long departmentId) { return dao.insertSnapshot(reviewId, applicationId, departmentId); }
    @Override public Optional<Map<String, Object>> reviewView(long id) { return dao.review(id); }

    @Override
    public Optional<AccessReviewAggregate> findReview(long id) {
        return dao.review(id).map(row -> new AccessReviewAggregate(
                number(row.get("id")),
                (String) row.get("name"),
                number(row.get("applicationId")),
                nullableLong(row.get("departmentId")),
                (String) row.get("status")
        ));
    }

    @Override public List<Map<String, Object>> reviews(Long applicationId, DomainVisibility visibility, String status) {
        return dao.reviews(applicationId, toVisibility(visibility), status);
    }
    @Override public PageSlice reviewItems(long reviewId, String decision, int page, int size) {
        var p = dao.reviewItems(reviewId, decision, page, size);
        return new PageSlice(p.items(), p.total());
    }
    @Override public Optional<String> lockReviewStatus(long reviewId) { return dao.lockReview(reviewId); }
    @Override public int decideReviewItem(long itemId, long reviewId, String decision, String actor, String comment) {
        return dao.decideItem(itemId, reviewId, decision, actor, comment);
    }

    @Override
    public List<AccessReviewAggregate.RevocationCandidate> pendingRevocations(long reviewId) {
        return dao.revocations(reviewId).stream()
                .map(row -> new AccessReviewAggregate.RevocationCandidate(
                        number(row.get("id")),
                        nullableLong(row.get("userId")),
                        nullableLong(row.get("roleId")),
                        nullableLong(row.get("departmentId")),
                        (String) row.get("grantId")))
                .toList();
    }

    @Override public int revokeMatchingGrant(long userId, long roleId, String grantId) { return dao.revokeGrant(userId, roleId, grantId); }
    @Override public void markReviewItemApplied(long itemId, boolean skipped) { dao.markApplied(itemId, skipped); }
    @Override public int closeReview(long reviewId, String actor, String summary) { return dao.closeReview(reviewId, actor, summary); }

    private static long number(Object value) { return ((Number) value).longValue(); }
    private static Long nullableLong(Object value) { return value == null ? null : ((Number) value).longValue(); }
}
