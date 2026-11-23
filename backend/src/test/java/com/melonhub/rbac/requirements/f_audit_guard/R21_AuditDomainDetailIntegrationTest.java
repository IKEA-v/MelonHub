package com.melonhub.rbac.requirements.f_audit_guard;

import static org.assertj.core.api.Assertions.assertThat;

import com.melonhub.rbac.dao.Visibility;
import com.melonhub.rbac.requirements.support.RbacIntegrationSupport;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R21（见 doc/requirements.md）。 */
class R21_AuditDomainDetailIntegrationTest extends RbacIntegrationSupport {

    @SuppressWarnings("unchecked")
    @DisplayName("R21 审计日志记录隔离域标识与变更明细")
    @Test void auditRecordsDomainIdsAndChangeDetails() {
        var events = r.events(d1, a1, Visibility.ALL, null, "ROLE_PERMISSIONS_UPDATED", null, null, null, 1, 20);
        assertThat(events.get("total")).isEqualTo(2L);
        assertThat((List<Map<String, Object>>) events.get("items")).allSatisfy(e -> assertThat((String) e.get("detail")).startsWith("新增 item:"));
        assertThat(r.events(null, null, new Visibility(List.of(a2), null), null, "ROLE_PERMISSIONS_UPDATED", null, null, null, 1, 20).get("total")).isEqualTo(1L);
    }
}
