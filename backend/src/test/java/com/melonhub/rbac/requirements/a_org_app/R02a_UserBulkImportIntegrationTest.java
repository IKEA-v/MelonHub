package com.melonhub.rbac.requirements.a_org_app;

import static org.assertj.core.api.Assertions.assertThat;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.requirements.support.GovernanceIntegrationSupport;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R2a（见 doc/requirements.md）。 */
class R02a_UserBulkImportIntegrationTest extends GovernanceIntegrationSupport {

    @DisplayName("R2a 用户批量导入幂等创建更新并逐行报错")
    @Test void bulkImportCreatesUpdatesAndReportsRowErrors() {
        var result = g.importUsers(new Requests.UserImport(List.of(
                new Requests.UserImportRow("新员工", external + "-new", "new@example.com", List.of(code1, code2)),
                new Requests.UserImportRow("改名", external, "", List.of(code1)),
                new Requests.UserImportRow("坏行", external + "-bad", "", List.of("no-such-dept")))), "admin");
        assertThat(((Number) result.get("created")).intValue()).isEqualTo(1);
        assertThat(((Number) result.get("updated")).intValue()).isEqualTo(1);
        assertThat(((List<?>) result.get("failed")).size()).isEqualTo(1);
        var imported = db.queryForMap("SELECT name FROM users WHERE external_id=?", external + "-new");
        assertThat(imported.get("name")).isEqualTo("新员工");
        assertThat(db.queryForObject("SELECT COUNT(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.external_id=?", Long.class, external + "-new"))
                .isEqualTo(2);
        assertThat(db.queryForObject("SELECT COUNT(*) FROM memberships WHERE user_id=?", Long.class, u1)).isEqualTo(2);
    }
}
