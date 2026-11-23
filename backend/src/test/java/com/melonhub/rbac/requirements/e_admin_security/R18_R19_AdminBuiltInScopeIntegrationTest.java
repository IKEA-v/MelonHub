package com.melonhub.rbac.requirements.e_admin_security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.requirements.support.SecurityIntegrationSupport;
import com.melonhub.rbac.security.AdminPrincipal;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/** 对应需求：R18、R19（见 doc/requirements.md）。 */
class R18_R19_AdminBuiltInScopeIntegrationTest extends SecurityIntegrationSupport {

    @DisplayName("R18 审计员仅可读所有视图不可执行任何写操作")
    @Test void auditorCanReadButNotWrite() throws Exception {
        String token = login(account(AdminPrincipal.AUDITOR, null));
        mvc.perform(get("/api/admin/users").header("Authorization", token)).andExpect(status().isOk()).andExpect(jsonPath("$.total").exists());
        mvc.perform(get("/api/admin/audit").header("Authorization", token)).andExpect(status().isOk());
        mvc.perform(post("/api/admin/departments").header("Authorization", token).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("name", "x", "code", "x-" + suffix)))).andExpect(status().isForbidden());
        mvc.perform(post("/api/admin/roles").param("departmentId", "" + d1).param("applicationId", "" + a1).header("Authorization", token)
                .contentType(MediaType.APPLICATION_JSON).content(json(Map.of("name", "R", "code", "r")))).andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/accounts").header("Authorization", token)).andExpect(status().isForbidden());
    }

    @DisplayName("R19 软件管理员严格受限于被分配软件范围")
    @Test void applicationAdministratorIsConfinedToAssignedApplications() throws Exception {
        String token = login(account(AdminPrincipal.APP_ADMIN, List.of(a1)));
        mvc.perform(get("/api/auth/me").header("Authorization", token)).andExpect(jsonPath("$.applicationIds[0]").value(a1));
        mvc.perform(get("/api/admin/applications").header("Authorization", token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1)).andExpect(jsonPath("$[0].id").value(a1));
        mvc.perform(post("/api/admin/roles").param("departmentId", "" + d1).param("applicationId", "" + a1).header("Authorization", token)
                .contentType(MediaType.APPLICATION_JSON).content(json(Map.of("name", "R", "code", "r")))).andExpect(status().isOk());
        mvc.perform(post("/api/admin/roles").param("departmentId", "" + d1).param("applicationId", "" + a2).header("Authorization", token)
                .contentType(MediaType.APPLICATION_JSON).content(json(Map.of("name", "R", "code", "r")))).andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/roles").param("departmentId", "" + d1).param("applicationId", "" + a2).header("Authorization", token)).andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/audit").param("applicationId", "" + a2).header("Authorization", token)).andExpect(status().isOk()).andExpect(jsonPath("$.total").value(0));
        mvc.perform(post("/api/admin/applications/" + a2 + "/keys").header("Authorization", token).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("name", "k")))).andExpect(status().isForbidden());
        mvc.perform(post("/api/admin/applications/" + a1 + "/keys").header("Authorization", token).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("name", "k")))).andExpect(status().isOk()).andExpect(jsonPath("$.apiKey").exists());
        mvc.perform(post("/api/admin/departments").header("Authorization", token).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("name", "x", "code", "x-" + suffix)))).andExpect(status().isForbidden());
        mvc.perform(patch("/api/admin/applications/" + a1 + "/status").header("Authorization", token).contentType(MediaType.APPLICATION_JSON)
                .content("{\"enabled\":false}")).andExpect(status().isForbidden());
    }

    @DisplayName("R18 账号管理功能仅限授权管理员访问")
    @Test void accountManagementIsReservedForSuperAdministrators() throws Exception {
        String admin = login(account(AdminPrincipal.ADMIN, null));
        mvc.perform(get("/api/admin/accounts").header("Authorization", admin)).andExpect(status().isForbidden());
        String root = login(account(AdminPrincipal.SUPER_ADMIN, null));
        mvc.perform(get("/api/admin/accounts").header("Authorization", root)).andExpect(status().isOk());
        mvc.perform(post("/api/admin/accounts").header("Authorization", root).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("username", "short-" + suffix, "role", "ADMIN", "password", "too-short")))).andExpect(status().isBadRequest());
        mvc.perform(put("/api/admin/accounts/" + auth.principal("super-admin-" + suffix).id()).header("Authorization", root).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("role", "ADMIN", "enabled", true)))).andExpect(status().isBadRequest());
    }

    @DisplayName("R19 平台禁止停用或删除最后一位启用的超级管理员")
    @Test void theLastEnabledSuperAdministratorCannotBeRemoved() {
        assertThatThrownBy(() -> auth.updateAccount(auth.principal(bootstrap).id(), new Requests.AccountUpdate(null, AdminPrincipal.ADMIN, true, null), ROOT))
                .isInstanceOf(ApiException.class).hasMessageContaining("超级管理员");
        assertThatThrownBy(() -> auth.deleteAccount(auth.principal(bootstrap).id(), ROOT)).isInstanceOf(ApiException.class).hasMessageContaining("超级管理员");
    }
}
