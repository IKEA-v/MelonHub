package com.melonhub.rbac.service.ddd.domain.model;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 系统状态看板领域报告模型：守护数据库不可达或半途异常时输出固定键集合且丢弃半截数据的降级契约。
 */
public final class SystemStatusReport {
    private static final List<String> DATABASE_DETAILS =
            List.of("counts", "pendingRequests", "openReviews", "webhookBacklog", "expiringIn7Days", "audit");

    private SystemStatusReport() {}

    public static Map<String, Object> degraded(String version, long uptimeSeconds, String javaVersion,
                                               String cacheHealth, long databaseLatencyMs) {
        var result = base(version, uptimeSeconds, javaVersion, cacheHealth, "DOWN", databaseLatencyMs);
        for (String key : DATABASE_DETAILS) result.put(key, null);
        return result;
    }

    public static Map<String, Object> healthy(String version, long uptimeSeconds, String javaVersion,
                                              String cacheHealth, long databaseLatencyMs,
                                              Map<String, Object> counts, long pendingRequests, long openReviews,
                                              long webhookBacklog, long expiringIn7Days, Map<String, Object> auditState) {
        var result = base(version, uptimeSeconds, javaVersion, cacheHealth, "UP", databaseLatencyMs);
        result.put("counts", counts);
        result.put("pendingRequests", pendingRequests);
        result.put("openReviews", openReviews);
        result.put("webhookBacklog", webhookBacklog);
        result.put("expiringIn7Days", expiringIn7Days);
        result.put("audit", auditState);
        return result;
    }

    private static Map<String, Object> base(String version, long uptimeSeconds, String javaVersion,
                                            String cacheHealth, String database, long latencyMs) {
        var result = new LinkedHashMap<String, Object>();
        result.put("version", version);
        result.put("uptimeSeconds", uptimeSeconds);
        result.put("javaVersion", javaVersion);
        result.put("cache", cacheHealth);
        result.put("database", database);
        result.put("databaseLatencyMs", latencyMs);
        return result;
    }
}
