package com.melonhub.rbac.requirements.b_rbac_domain;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.requirements.support.SecurityIntegrationSupport;
import com.melonhub.rbac.security.AdminPrincipal;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/** 对应需求：R7（见 doc/requirements.md）。 */
class R07_BatchGrantScopeIntegrationTest extends SecurityIntegrationSupport {

    @DisplayName("R7 批量授权严格遵守管理员软件写范围")
    @Test void batchGrantHonorsApplicationWriteScope() throws Exception {
        String manager = account(AdminPrincipal.APP_ADMIN, List.of(a1));
        String bearer = "Bearer " + auth.login(new Requests.Login(manager, PASSWORD)).get("token");
        long user = r.user(new Requests.User("Batch", "batch-" + suffix, "", List.of(d1)), null, "test");
        long role = r.role(new Requests.Role("Batch", "batch", ""), null, d1, a1, "test");
        String body = json(new Requests.BatchUserRoles(List.of(user), List.of(role), null));
        mvc.perform(post("/api/admin/assignments/batch").header("Authorization", bearer)
                .param("departmentId", String.valueOf(d1)).param("applicationId", String.valueOf(a2))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
        mvc.perform(post("/api/admin/assignments/batch").header("Authorization", bearer)
                .param("departmentId", String.valueOf(d1)).param("applicationId", String.valueOf(a1))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk()).andExpect(jsonPath("$.grantsAdded").value(1));
        String auditor = account(AdminPrincipal.AUDITOR, List.of());
        String readOnly = "Bearer " + auth.login(new Requests.Login(auditor, PASSWORD)).get("token");
        mvc.perform(post("/api/admin/assignments/batch").header("Authorization", readOnly)
                .param("departmentId", String.valueOf(d1)).param("applicationId", String.valueOf(a1))
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
    }
}
