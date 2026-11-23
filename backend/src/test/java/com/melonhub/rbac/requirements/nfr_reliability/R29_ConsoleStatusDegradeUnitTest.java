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
import com.melonhub.rbac.service.ConsoleService;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;

/** 对应需求：R29（见 doc/requirements.md）。 */
class R29_ConsoleStatusDegradeUnitTest {
    private static final List<String> DETAILS = List.of("counts", "pendingRequests", "openReviews", "webhookBacklog", "expiringIn7Days", "audit");
    private final RbacDao dao = mock(RbacDao.class);
    private final GovernanceDao governance = mock(GovernanceDao.class);
    private final PermissionCache cache = mock(PermissionCache.class);
    private final ConsoleService console = new ConsoleService(dao, governance, mock(WebhookDao.class), mock(AuditDao.class), cache);

    @DisplayName("R29 数据库不可达时系统状态看板仍返回完整键结构")
    @Test void anUnreachableDatabaseStillAnswersWithEveryKey() {
        when(dao.healthy()).thenThrow(new DataAccessResourceFailureException("down"));
        var status = console.status(new Visibility(List.of(), List.of()));
        assertThat(status).containsEntry("database", "DOWN").containsKeys(DETAILS.toArray(String[]::new));
        DETAILS.forEach(key -> assertThat(status.get(key)).as(key).isNull());
    }

    @DisplayName("R29 数据库查询半途失败时丢弃半截数据并回报 DOWN")
    @Test void aDatabaseFailingHalfwayDropsWhatItAlreadyReturned() {
        when(dao.healthy()).thenReturn(true);
        when(dao.consoleCounts()).thenReturn(Map.<String, Object>of("users", 3L));
        when(governance.pendingCount(any())).thenThrow(new DataAccessResourceFailureException("lost"));
        var status = console.status(new Visibility(List.of(), List.of()));
        assertThat(status).containsEntry("database", "DOWN").containsKeys(DETAILS.toArray(String[]::new));
        DETAILS.forEach(key -> assertThat(status.get(key)).as(key).isNull());
    }
}
