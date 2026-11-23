package com.melonhub.rbac.requirements.a_org_app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.requirements.support.SecurityIntegrationSupport;
import com.melonhub.rbac.security.AdminPrincipal;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R2、R21（见 doc/requirements.md）。 */
class R02_UserAndAuditExportIntegrationTest extends SecurityIntegrationSupport {

    @DisplayName("R2/R21 用户与审计导出仅返回可见范围内的全部筛选行")
    @Test void exportsIncludeAllFilteredUsersAndOnlyVisibleAuditRows() throws Exception {
        String manager = account(AdminPrincipal.APP_ADMIN, List.of(a1));
        String bearer = "Bearer " + auth.login(new Requests.Login(manager, PASSWORD)).get("token");
        var rows = new java.util.ArrayList<Object[]>();
        for (int i = 0; i < 205; i++) rows.add(new Object[]{"Export", "export-" + suffix + "-" + i, ""});
        db.batchUpdate("INSERT INTO users(name,external_id,email) VALUES (?,?,?)", rows);
        mvc.perform(get("/api/admin/users/export").header("Authorization", bearer).param("keyword", "export-" + suffix))
                .andExpect(status().isOk()).andExpect(jsonPath("$.total").value(205)).andExpect(jsonPath("$.items.length()").value(205));
        r.audit("export-" + suffix, "EXPORT_TEST", "visible", d1, a1, "");
        r.audit("export-" + suffix, "EXPORT_TEST", "hidden", d1, a2, "");
        mvc.perform(get("/api/admin/audit/export").header("Authorization", bearer).param("actor", "export-" + suffix))
                .andExpect(status().isOk()).andExpect(jsonPath("$.total").value(1)).andExpect(jsonPath("$.items[0].target").value("visible"));
    }
}
