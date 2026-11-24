package com.melonhub.rbac.requirements.nfr_reliability;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.melonhub.rbac.cache.PermissionCache;
import com.melonhub.rbac.dao.AuditDao;
import com.melonhub.rbac.dao.GovernanceDao;
import com.melonhub.rbac.dao.RbacDao;
import com.melonhub.rbac.dao.Visibility;
import com.melonhub.rbac.dao.WebhookDao;
import com.melonhub.rbac.service.ddd.application.DddConsoleService;
import com.melonhub.rbac.service.ddd.infrastructure.JpaConsoleMetricsAdapter;
import com.melonhub.rbac.service.port.ConsoleUseCase;
import com.melonhub.rbac.service.structured.StructuredConsoleService;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataAccessResourceFailureException;

/** 对应需求：R29（见 doc/requirements.md）。覆盖结构化与 DDD 双策略。 */
class R29_ConsoleStatusDegradeUnitTest {
    private static final List<String> DETAILS = List.of("counts", "pendingRequests", "openReviews", "webhookBacklog", "expiringIn7Days", "audit");

    private static ConsoleUseCase build(String strategy, RbacDao dao, GovernanceDao governance, PermissionCache cache) {
        var webhooks = mock(WebhookDao.class);
        var audit = mock(AuditDao.class);
        return "ddd".equals(strategy)
                ? new DddConsoleService(new JpaConsoleMetricsAdapter(dao, governance, webhooks, audit, cache))
                : new StructuredConsoleService(dao, governance, webhooks, audit, cache);
    }

    @ParameterizedTest(name = "[{0}]")
    @ValueSource(strings = { "structured", "ddd" })
    @DisplayName("R29 数据库不可达时系统状态看板仍返回完整键结构")
    void anUnreachableDatabaseStillAnswersWithEveryKey(String strategy) {
        var dao = mock(RbacDao.class);
        var governance = mock(GovernanceDao.class);
        var cache = mock(PermissionCache.class);
        when(dao.healthy()).thenThrow(new DataAccessResourceFailureException("down"));
        var status = build(strategy, dao, governance, cache).status(new Visibility(List.of(), List.of()));
        assertThat(status).containsEntry("database", "DOWN").containsKeys(DETAILS.toArray(String[]::new));
        DETAILS.forEach(key -> assertThat(status.get(key)).as(key).isNull());
    }

    @ParameterizedTest(name = "[{0}]")
    @ValueSource(strings = { "structured", "ddd" })
    @DisplayName("R29 数据库查询半途失败时丢弃半截数据并回报 DOWN")
    void aDatabaseFailingHalfwayDropsWhatItAlreadyReturned(String strategy) {
        var dao = mock(RbacDao.class);
        var governance = mock(GovernanceDao.class);
        var cache = mock(PermissionCache.class);
        when(dao.healthy()).thenReturn(true);
        when(dao.consoleCounts()).thenReturn(Map.<String, Object>of("users", 3L));
        when(governance.pendingCount(any())).thenThrow(new DataAccessResourceFailureException("lost"));
        var status = build(strategy, dao, governance, cache).status(new Visibility(List.of(), List.of()));
        assertThat(status).containsEntry("database", "DOWN").containsKeys(DETAILS.toArray(String[]::new));
        DETAILS.forEach(key -> assertThat(status.get(key)).as(key).isNull());
    }
}
