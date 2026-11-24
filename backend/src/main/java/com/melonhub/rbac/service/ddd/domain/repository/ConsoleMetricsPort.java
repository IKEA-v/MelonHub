package com.melonhub.rbac.service.ddd.domain.repository;

import com.melonhub.rbac.service.ddd.domain.value.DomainVisibility;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * 控制台全局检索与系统状态看板领域查询端口。
 */
public interface ConsoleMetricsPort {
    List<Map<String, Object>> searchUsers(String keyword, DomainVisibility visibility);

    List<Map<String, Object>> searchDepartments(String keyword, DomainVisibility visibility);

    List<Map<String, Object>> searchApplications(String keyword, DomainVisibility visibility);

    List<Map<String, Object>> searchRoles(String keyword, DomainVisibility visibility);

    String cacheHealth();

    boolean databaseHealthy();

    Map<String, Object> consoleCounts();

    long pendingRequestCount(DomainVisibility visibility);

    long openReviewCount(DomainVisibility visibility);

    long webhookBacklog();

    long expiringAssignmentCount(Instant deadline);

    Map<String, Object> auditSealState();
}
