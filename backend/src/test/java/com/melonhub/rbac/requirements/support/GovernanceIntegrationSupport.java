package com.melonhub.rbac.requirements.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.melonhub.rbac.CloudTestDatabaseGuard;
import com.melonhub.rbac.dao.AuditDao;
import com.melonhub.rbac.dao.GovernanceDao;
import com.melonhub.rbac.dao.Visibility;
import com.melonhub.rbac.dao.WebhookDao;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.security.GlobalRateLimiter;
import com.melonhub.rbac.service.port.AuditSealUseCase;
import com.melonhub.rbac.service.port.AuthUseCase;
import com.melonhub.rbac.service.port.ConsoleUseCase;
import com.melonhub.rbac.service.port.ContextUseCase;
import com.melonhub.rbac.service.port.GovernanceUseCase;
import com.melonhub.rbac.service.port.RbacUseCase;
import com.melonhub.rbac.service.port.WebhookUseCase;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

/** 授权治理、审批、复核、Webhook、MFA 与审计链集成测试共用固件。 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles("test")
@ContextConfiguration(initializers = CloudTestDatabaseGuard.class)
public abstract class GovernanceIntegrationSupport {
    protected static final String ACTOR = "gov-test";

    @Autowired protected RbacUseCase r;
    @Autowired protected ContextUseCase c;
    @Autowired protected GovernanceUseCase g;
    @Autowired protected ConsoleUseCase console;
    @Autowired protected WebhookUseCase webhooks;
    @Autowired protected AuditSealUseCase sealer;
    @Autowired protected AuthUseCase auth;
    @Autowired protected GlobalRateLimiter globalRateLimiter;
    @Autowired protected GovernanceDao gov;
    @Autowired protected AuditDao auditDao;
    @Autowired protected WebhookDao webhookDao;
    @Autowired protected MockMvc mvc;
    @Value("${melonhub.admin-username}") protected String bootstrap;
    @Autowired protected ObjectMapper mapper;
    @Autowired protected JdbcTemplate db;

    protected long d1, d2, a1, u1, u2, r1, r2;
    protected String external, external2, code1, code2, key1;

    @BeforeEach
    protected void fixture() {
        String suffix = Credentials.token().substring(0, 12);
        external = "gov-" + suffix;
        external2 = external + "-second";
        code1 = "gd1-" + suffix;
        code2 = "gd2-" + suffix;
        d1 = r.department(new Requests.Department("Gov One", code1), null, ACTOR);
        d2 = r.department(new Requests.Department("Gov Two", code2), null, ACTOR);
        var app = r.application(new Requests.Application("Gov App", "ga-" + suffix, ""), ACTOR);
        a1 = ((Number) app.get("id")).longValue();
        key1 = (String) app.get("apiKey");
        u1 = r.user(new Requests.User("GovUser", external, "", List.of(d1, d2)), null, ACTOR);
        u2 = r.user(new Requests.User("GovSecond", external2, "", List.of(d1)), null, ACTOR);
        long p1 = r.permission(new Requests.Permission("Read", "item:read", "item", "read"), null, d1, a1, ACTOR);
        long p2 = r.permission(new Requests.Permission("Write", "item:write", "item", "write"), null, d1, a1, ACTOR);
        r1 = r.role(new Requests.Role("Reader", "reader", ""), null, d1, a1, ACTOR);
        r2 = r.role(new Requests.Role("Writer", "writer", ""), null, d1, a1, ACTOR);
        r.rolePermissions(r1, d1, a1, List.of(p1), ACTOR);
        r.rolePermissions(r2, d1, a1, List.of(p2), ACTOR);
        r.userRoles(u1, d1, a1, List.of(r1), ACTOR);
    }

    protected String issue() {
        return (String) c.issue(a1, new Requests.Context(external, d1, null), ACTOR).get("contextToken");
    }

    protected long requestId(Map<String, Object> request) {
        return ((Number) request.get("id")).longValue();
    }

    protected void rbacAudit(int i) {
        r.userStatus(u2, i % 2 == 0, ACTOR + "-chain");
    }

    protected long lastAuditId() {
        return db.queryForObject("SELECT MAX(id) FROM audit_events", Long.class);
    }

    protected long sealSeq(long id) {
        return db.queryForObject("SELECT seal_seq FROM audit_events WHERE id=?", Long.class, id);
    }

    protected String cacheHealth() {
        try {
            return console.status(Visibility.ALL).get("cache").toString();
        } catch (RuntimeException e) {
            return "DOWN";
        }
    }

    protected Instant expiresAt(long user, long role) {
        var at = db.queryForObject("SELECT expires_at FROM user_roles WHERE user_id=? AND role_id=?", Timestamp.class, user, role);
        return at == null ? null : at.toInstant();
    }

    protected String grantId(long user, long role) {
        return db.queryForObject("SELECT grant_id FROM user_roles WHERE user_id=? AND role_id=?", String.class, user, role);
    }
}
