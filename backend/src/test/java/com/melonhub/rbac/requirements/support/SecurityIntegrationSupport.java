package com.melonhub.rbac.requirements.support;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.melonhub.rbac.CloudTestDatabaseGuard;
import com.melonhub.rbac.dao.AuthDao;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.AdminPrincipal;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.service.AuthService;
import com.melonhub.rbac.service.RbacService;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

/** 管理员认证、会话凭据、范围隔离与安全守卫集成测试共用固件。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles("test")
@ContextConfiguration(initializers = CloudTestDatabaseGuard.class)
public abstract class SecurityIntegrationSupport {
    protected static final String PASSWORD = "Test-Only-Passw0rd";

    /** A root of the administrator tree that manages every account but, being disabled, is not counted as an enabled super administrator. */
    protected AdminPrincipal ROOT;

    @Autowired protected MockMvc mvc;
    @Autowired protected ObjectMapper mapper;
    @Autowired protected RbacService r;
    @Autowired protected AuthService auth;
    @Autowired protected AuthDao authDao;
    @Autowired protected JdbcTemplate db;
    @Value("${melonhub.admin-username}") protected String bootstrap;

    protected long d1, a1, a2;
    protected String suffix;

    @BeforeEach
    protected void fixture() {
        suffix = Credentials.token().substring(0, 10);
        String root = "security-root-" + suffix;
        db.update("INSERT INTO admin_accounts(username,display_name,role,password_hash,enabled) VALUES (?,'root','SUPER_ADMIN','-',FALSE)", root);
        ROOT = auth.principal(root);
        d1 = r.department(new Requests.Department("Security", "sec-" + suffix), null, "test");
        a1 = ((Number) r.application(new Requests.Application("SecOne", "s1-" + suffix, ""), "test").get("id")).longValue();
        a2 = ((Number) r.application(new Requests.Application("SecTwo", "s2-" + suffix, ""), "test").get("id")).longValue();
    }

    protected String account(String role, List<Long> applications) {
        String name = role.toLowerCase(Locale.ROOT).replace('_', '-') + "-" + suffix;
        auth.createAccount(new Requests.Account(name, null, role, PASSWORD, true, applications), ROOT);
        return name;
    }

    protected ResultActions attempt(String user, String password) throws Exception {
        return mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("username", user, "password", password))));
    }

    protected String login(String user) throws Exception {
        String body = attempt(user, PASSWORD).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return "Bearer " + mapper.readTree(body).get("token").asText();
    }

    protected String json(Object value) throws Exception {
        return mapper.writeValueAsString(value);
    }
}
