package com.melonhub.rbac.service.ddd.application;

import com.melonhub.rbac.dao.Visibility;
import com.melonhub.rbac.service.ddd.domain.model.SystemStatusReport;
import com.melonhub.rbac.service.ddd.domain.repository.ConsoleMetricsPort;
import com.melonhub.rbac.service.port.ConsoleUseCase;
import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

/**
 * DDD 应用服务：控制台全局检索与容错降级系统状态看板。
 */
@Service
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class DddConsoleService implements ConsoleUseCase {
    private final ConsoleMetricsPort metrics;

    public DddConsoleService(ConsoleMetricsPort metrics) {
        this.metrics = metrics;
    }

    @Override
    public Map<String, Object> search(String keyword, Visibility visible) {
        var result = new LinkedHashMap<String, Object>();
        String query = keyword == null ? "" : keyword.strip();
        if (query.isEmpty() || query.length() > 64) {
            result.put("users", List.of());
            result.put("departments", List.of());
            result.put("applications", List.of());
            result.put("roles", List.of());
            return result;
        }
        var domainVisible = DddBoundary.toDomainVisibility(visible);
        result.put("users", metrics.searchUsers(query, domainVisible));
        result.put("departments", metrics.searchDepartments(query, domainVisible));
        result.put("applications", metrics.searchApplications(query, domainVisible));
        result.put("roles", metrics.searchRoles(query, domainVisible));
        return result;
    }

    @Override
    public Map<String, Object> status(Visibility visible) {
        String version = getClass().getPackage().getImplementationVersion() == null
                ? "dev" : getClass().getPackage().getImplementationVersion();
        long uptimeSeconds = ManagementFactory.getRuntimeMXBean().getUptime() / 1000;
        String javaVersion = System.getProperty("java.version");
        var cacheHealth = metrics.cacheHealth();
        long started = System.nanoTime();
        boolean healthy;
        try {
            healthy = metrics.databaseHealthy();
        } catch (RuntimeException e) {
            healthy = false;
        }
        long latencyMs = (System.nanoTime() - started) / 1_000_000;
        if (!healthy) {
            return SystemStatusReport.degraded(version, uptimeSeconds, javaVersion, cacheHealth, latencyMs);
        }
        var domainVisible = DddBoundary.toDomainVisibility(visible);
        try {
            return SystemStatusReport.healthy(
                    version, uptimeSeconds, javaVersion, cacheHealth, latencyMs,
                    metrics.consoleCounts(),
                    metrics.pendingRequestCount(domainVisible),
                    metrics.openReviewCount(domainVisible),
                    metrics.webhookBacklog(),
                    metrics.expiringAssignmentCount(Instant.now().plus(7, ChronoUnit.DAYS)),
                    metrics.auditSealState()
            );
        } catch (DataAccessException e) {
            return SystemStatusReport.degraded(version, uptimeSeconds, javaVersion, cacheHealth, latencyMs);
        }
    }
}
