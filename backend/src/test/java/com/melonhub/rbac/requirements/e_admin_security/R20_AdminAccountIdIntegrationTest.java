package com.melonhub.rbac.requirements.e_admin_security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.melonhub.rbac.CloudTestDatabaseGuard;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.service.port.AuthUseCase;
import java.util.Map;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

/** 验证管理员账号使用独立数字主键，并支持按主键调用管理接口。 对应需求：R20（见 doc/requirements.md）。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles("test")
@ContextConfiguration(initializers = CloudTestDatabaseGuard.class)
class R20_AdminAccountIdIntegrationTest {
    private static final String PASSWORD = "Admin-Id-Test-Passw0rd";

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired AuthUseCase auth;
    @Value("${melonhub.admin-username}") String bootstrap;

    @Test
    @DisplayName("R20 管理员账号列表与数字主键接口暴露稳定 id 与 parentId")
    void accountListAndNumericEndpointExposeStableId() throws Exception {
        String suffix = Credentials.token().substring(0, 10);
        String operator = "id-root-" + suffix;
        String username = "id-admin-" + suffix;
        long operatorId = auth.createAccount(new Requests.Account(operator, null, "SUPER_ADMIN", PASSWORD, true, null),
                auth.principal(bootstrap));
        var login = auth.login(new Requests.Login(operator, PASSWORD));
        assertThat(login.get("id")).isEqualTo(operatorId);
        String token = "Bearer " + login.get("token");
        mvc.perform(get("/api/auth/me").header("Authorization", token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(operatorId));

        String created = mvc.perform(post("/api/admin/accounts").header("Authorization", token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("username", username, "displayName", "ID 管理员",
                                "role", "AUDITOR", "password", PASSWORD, "parentId", operatorId))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        long id = mapper.readTree(created).path("id").asLong();
        assertThat(id).isPositive().isNotEqualTo(operatorId);

        String body = mvc.perform(get("/api/admin/accounts").header("Authorization", token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var account = StreamSupport.stream(mapper.readTree(body).spliterator(), false)
                .filter(row -> username.equals(row.path("username").asText())).findFirst().orElseThrow();
        assertThat(account.path("id").asLong()).isEqualTo(id);
        assertThat(account.path("parentId").asLong()).isEqualTo(operatorId);

        mvc.perform(put("/api/admin/accounts/" + id).header("Authorization", token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(new Requests.AccountUpdate("已更新", "AUDITOR", true, null))))
                .andExpect(status().isOk());
        mvc.perform(put("/api/admin/accounts/" + Long.MAX_VALUE).header("Authorization", token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(new Requests.AccountUpdate("已更新", "AUDITOR", true, null))))
                .andExpect(status().isNotFound());
    }
}
