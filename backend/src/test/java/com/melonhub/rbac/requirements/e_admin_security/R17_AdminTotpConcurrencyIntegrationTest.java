package com.melonhub.rbac.requirements.e_admin_security;

import static org.assertj.core.api.Assertions.assertThat;

import com.melonhub.rbac.CloudTestDatabaseGuard;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.security.Totp;
import com.melonhub.rbac.service.AuthService;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

/**
 * Real multi-connection concurrency test (no {@code @Transactional}) verifying single-use TOTP enforcement.
 * 对应需求：R17（见 doc/requirements.md）。
 */
@SpringBootTest
@ActiveProfiles("test")
@ContextConfiguration(initializers = CloudTestDatabaseGuard.class)
class R17_AdminTotpConcurrencyIntegrationTest {
    private static final String ACTOR = "race-test";
    @Autowired AuthService auth;
    @Value("${melonhub.admin-username}") String bootstrap;
    @Autowired JdbcTemplate db;

    @DisplayName("R17 多线程并发登录不能重复使用同一个 TOTP 动态口令")
    @Test void concurrentLoginsCannotShareOneTotpCode() throws Exception {
        String username = "mfa-race-" + Credentials.token().substring(0, 8);
        String password = "mfa-password-123";
        auth.createAccount(new Requests.Account(username, "并发登录", "AUDITOR", password, true, null), auth.principal(bootstrap));
        var pool = Executors.newFixedThreadPool(4);
        try {
            var principal = auth.principal(username);
            String secret = (String) auth.setupMfa(principal).get("secret");
            auth.confirmMfa(principal, Totp.codeAt(secret, Totp.currentStep()));
            String code = Totp.codeAt(secret, Totp.currentStep() + 1);
            var start = new CountDownLatch(1);
            var attempts = new ArrayList<Future<String>>();
            for (int i = 0; i < 4; i++) attempts.add(pool.submit(() -> {
                start.await();
                try {
                    auth.login(new Requests.Login(username, password, code));
                    return "OK";
                } catch (ApiException e) {
                    return e.code();
                }
            }));
            start.countDown();
            var outcomes = new ArrayList<String>();
            for (var attempt : attempts) outcomes.add(attempt.get(30, TimeUnit.SECONDS));
            assertThat(outcomes).containsOnlyOnce("OK");
            assertThat(outcomes.stream().filter(outcome -> !outcome.equals("OK")).toList()).hasSize(3).containsOnly("MFA_INVALID");
        } finally {
            pool.shutdownNow();
            db.update("DELETE FROM admin_accounts WHERE username=?", username);
            db.update("DELETE FROM audit_events WHERE actor IN (?,?) OR target=?", ACTOR, username, username);
        }
    }
}
