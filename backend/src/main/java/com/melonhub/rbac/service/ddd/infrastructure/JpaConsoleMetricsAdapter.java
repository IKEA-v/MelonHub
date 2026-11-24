package com.melonhub.rbac.service.ddd.infrastructure;

import static com.melonhub.rbac.service.ddd.infrastructure.JpaRbacRepositoryAdapter.toVisibility;
import static com.melonhub.rbac.service.ddd.infrastructure.JpaRbacRepositoryAdapter.ts;

import com.melonhub.rbac.cache.PermissionCache;
import com.melonhub.rbac.dao.AuditDao;
import com.melonhub.rbac.dao.GovernanceDao;
import com.melonhub.rbac.dao.RbacDao;
import com.melonhub.rbac.dao.WebhookDao;
import com.melonhub.rbac.service.ddd.domain.repository.ConsoleMetricsPort;
import com.melonhub.rbac.service.ddd.domain.value.DomainVisibility;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** DDD 基础设施适配器：将 {@link ConsoleMetricsPort} 桥接到各只读 DAO 与缓存健康探针。 */
@Component
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class JpaConsoleMetricsAdapter implements ConsoleMetricsPort {
    private final RbacDao rbac;
    private final GovernanceDao governance;
    private final WebhookDao webhooks;
    private final AuditDao audit;
    private final PermissionCache cache;

    public JpaConsoleMetricsAdapter(RbacDao rbac, GovernanceDao governance, WebhookDao webhooks, AuditDao audit, PermissionCache cache) {
        this.rbac = rbac;
        this.governance = governance;
        this.webhooks = webhooks;
        this.audit = audit;
        this.cache = cache;
    }

    @Override public List<Map<String, Object>> searchUsers(String keyword, DomainVisibility visibility) {
        return rbac.searchUsers(RbacDao.like(keyword), visibility.departments());
    }
    @Override public List<Map<String, Object>> searchDepartments(String keyword, DomainVisibility visibility) {
        return rbac.searchDepartments(RbacDao.like(keyword), visibility.departments());
    }
    @Override public List<Map<String, Object>> searchApplications(String keyword, DomainVisibility visibility) {
        return rbac.searchApplications(RbacDao.like(keyword), visibility.applications());
    }
    @Override public List<Map<String, Object>> searchRoles(String keyword, DomainVisibility visibility) {
        return rbac.searchRoles(RbacDao.like(keyword), toVisibility(visibility));
    }
    @Override public String cacheHealth() { return cache.health(); }
    @Override public boolean databaseHealthy() { return rbac.healthy(); }
    @Override public Map<String, Object> consoleCounts() { return rbac.consoleCounts(); }
    @Override public long pendingRequestCount(DomainVisibility visibility) { return governance.pendingCount(toVisibility(visibility)); }
    @Override public long openReviewCount(DomainVisibility visibility) { return governance.openReviewCount(toVisibility(visibility)); }
    @Override public long webhookBacklog() { return webhooks.backlog(); }
    @Override public long expiringAssignmentCount(Instant deadline) { return rbac.expiringCount(ts(deadline)); }
    @Override public Map<String, Object> auditSealState() { return audit.sealState(); }
}
