package com.melonhub.rbac.service.ddd.domain.model;

import com.melonhub.rbac.service.ddd.domain.value.DomainException;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * 定期权限复核聚合根：保护复核单 OPEN/CLOSED 状态机、条目决定合法性以及按快照 {@code grantId} 精确回收的总结规则。
 */
public final class AccessReviewAggregate {
    public static final List<String> VALID_STATUSES = List.of("OPEN", "CLOSED");
    public static final List<String> VALID_DECISIONS = List.of("PENDING", "KEEP", "REVOKE");

    public record RevocationCandidate(long itemId, Long userId, Long roleId, Long departmentId, String grantId) {
        public boolean canAttemptRevoke() {
            return userId != null && roleId != null;
        }
    }

    private final long id;
    private final String name;
    private final long applicationId;
    private final Long departmentId;
    private final String status;

    public AccessReviewAggregate(long id, String name, long applicationId, Long departmentId, String status) {
        this.id = id;
        this.name = name;
        this.applicationId = applicationId;
        this.departmentId = departmentId;
        this.status = status;
    }

    public static void validateStatusFilter(String status) {
        if (status != null && !status.isBlank() && !VALID_STATUSES.contains(status.strip())) {
            throw DomainException.bad("状态只能是 OPEN 或 CLOSED");
        }
    }

    public static void validateDecisionFilter(String decision) {
        if (decision != null && !decision.isBlank() && !VALID_DECISIONS.contains(decision.strip())) {
            throw DomainException.bad("决定只能是 PENDING、KEEP 或 REVOKE");
        }
    }

    public static void assertOpenStatus(String status) {
        if (!"OPEN".equals(status)) {
            throw DomainException.conflict("复核已关闭");
        }
    }

    public static Set<Long> orderedUsersToLock(List<RevocationCandidate> candidates) {
        var users = new TreeSet<Long>();
        for (var item : candidates) {
            if (item.userId() != null) users.add(item.userId());
        }
        return users;
    }

    public static String closeSummary(int revoked, int skipped) {
        return "回收 " + revoked + " 条授权"
                + (skipped == 0 ? "" : "，" + skipped + " 条在复核期间已变更或移除，未回收")
                + "，未决条目视为保留";
    }

    public long id() { return id; }
    public String name() { return name; }
    public long applicationId() { return applicationId; }
    public Long departmentId() { return departmentId; }
    public String status() { return status; }
}
