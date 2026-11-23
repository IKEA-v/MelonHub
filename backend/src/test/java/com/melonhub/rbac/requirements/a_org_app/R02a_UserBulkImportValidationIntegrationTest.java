package com.melonhub.rbac.requirements.a_org_app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.melonhub.rbac.requirements.support.SecurityIntegrationSupport;
import com.melonhub.rbac.security.AdminPrincipal;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/** 对应需求：R2a（见 doc/requirements.md）。 */
class R02a_UserBulkImportValidationIntegrationTest extends SecurityIntegrationSupport {

    @DisplayName("R2a 批量导入逐行报告非法数据而不整批失败")
    @Test void bulkImportReportsInvalidRowsInsteadOfRejectingTheRequest() throws Exception {
        String token = login(account(AdminPrincipal.ADMIN, null));
        var rows = java.util.Arrays.asList(
                Map.of("name", "导入一", "externalId", "imp-" + suffix, "departmentCodes", List.of("sec-" + suffix)),
                Map.of("name", "", "externalId", "imp2-" + suffix, "departmentCodes", List.of("sec-" + suffix)),
                Map.of("name", "缺部门", "externalId", "imp3-" + suffix),
                null);
        mvc.perform(post("/api/admin/users/import").header("Authorization", token).contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("users", rows))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.created").value(1))
                .andExpect(jsonPath("$.failed.length()").value(3))
                .andExpect(jsonPath("$.failed[0].line").value(2))
                .andExpect(jsonPath("$.failed[0].error").value(org.hamcrest.Matchers.containsString("name")))
                .andExpect(jsonPath("$.failed[1].error").value(org.hamcrest.Matchers.containsString("departmentCodes")))
                .andExpect(jsonPath("$.failed[2].line").value(4));
    }
}
