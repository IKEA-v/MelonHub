package com.melonhub.rbac.service.ddd.domain.repository;

import com.melonhub.rbac.service.ddd.domain.model.AccessRequestAggregate;
import com.melonhub.rbac.service.ddd.domain.model.AccessReviewAggregate;
import com.melonhub.rbac.service.ddd.domain.value.DomainVisibility;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 授权治理（角色申请审批与定期复核）领域仓储端口。
 */
public interface GovernanceRepositoryPort {
    PageSlice requests(Long applicationId, DomainVisibility visibility, String status, String keyword, int page, int size);

    Optional<Map<String, Object>> requestView(long id);

    Optional<AccessRequestAggregate> findRequest(long id);

    boolean pendingRequestExists(long userId, long roleId);

    long createRequest(long userId, long departmentId, long applicationId, long roleId, String reason, Integer durationDays, String actor);

    int decideRequest(long id, String status, String actor, String comment, Instant expiresAt);

    int cancelOwnRequest(long id, long userId);

    int cancelPendingByColumn(String column, long targetId, String comment);

    List<Map<String, Object>> requestsOfUser(long userId, long applicationId);

    long createReview(String name, long applicationId, Long departmentId, Instant dueAt, String actor);

    int insertReviewSnapshot(long reviewId, long applicationId, Long departmentId);

    Optional<Map<String, Object>> reviewView(long id);

    Optional<AccessReviewAggregate> findReview(long id);

    List<Map<String, Object>> reviews(Long applicationId, DomainVisibility visibility, String status);

    PageSlice reviewItems(long reviewId, String decision, int page, int size);

    Optional<String> lockReviewStatus(long reviewId);

    int decideReviewItem(long itemId, long reviewId, String decision, String actor, String comment);

    List<AccessReviewAggregate.RevocationCandidate> pendingRevocations(long reviewId);

    int revokeMatchingGrant(long userId, long roleId, String grantId);

    void markReviewItemApplied(long itemId, boolean skipped);

    int closeReview(long reviewId, String actor, String summary);
}
