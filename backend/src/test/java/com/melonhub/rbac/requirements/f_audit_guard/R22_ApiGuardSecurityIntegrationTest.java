package com.melonhub.rbac.requirements.f_audit_guard;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.melonhub.rbac.requirements.support.SecurityIntegrationSupport;
import java.net.URI;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** 对应需求：R22（见 doc/requirements.md）。 */
class R22_ApiGuardSecurityIntegrationTest extends SecurityIntegrationSupport {

    @ParameterizedTest
    @DisplayName("R22 非规范路径（分号/编码/双斜杠）不能绕过认证返回 400")
    @ValueSource(strings = {"/api;x=1/admin/users", "/%61pi/admin/users", "/api/admin;x/users", "/api/%61dmin/departments",
            "/api/admin/../admin/users", "/api//admin/users", "/api/./admin/users", "/api/admin/users/", "/api/admin/users;jsessionid=1"})
    void nonCanonicalPathsCannotBypassAuthentication(String path) throws Exception {
        mvc.perform(get(URI.create(path))).andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_PATH"));
    }

    @DisplayName("R22 除健康检查与登录外所有 /api 路径默认拒绝未认证请求")
    @Test void everyApiPathExceptHealthAndLoginNeedsCredentials() throws Exception {
        mvc.perform(get("/api/anything")).andExpect(status().isUnauthorized());
        mvc.perform(get("/API/admin/users")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/departments")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/health")).andExpect(status().isOk());
    }

    @DisplayName("R22 响应统一携带 X-Request-Id 与安全响应头")
    @Test void responsesCarryRequestIdAndSecurityHeaders() throws Exception {
        mvc.perform(get("/api/health").header("X-Request-Id", "trace-12345678"))
                .andExpect(header().string("X-Request-Id", "trace-12345678"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Cache-Control", "no-store"));
        mvc.perform(get("/api/admin/users").header("X-Request-Id", "bad id with spaces"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.requestId").exists())
                .andExpect(header().string("X-Request-Id", org.hamcrest.Matchers.not("bad id with spaces")));
    }
}
