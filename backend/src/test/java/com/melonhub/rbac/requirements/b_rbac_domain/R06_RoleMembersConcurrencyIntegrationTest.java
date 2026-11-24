package com.melonhub.rbac.requirements.b_rbac_domain;

import static org.assertj.core.api.Assertions.assertThat;

import com.melonhub.rbac.CloudTestDatabaseGuard;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.service.port.RbacUseCase;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Real multi-connection concurrency test (no {@code @Transactional}) verifying deadlock-free role member replacement.
 * 对应需求：R6（见 doc/requirements.md）。
 */
@SpringBootTest
@ActiveProfiles("test")
@ContextConfiguration(initializers = CloudTestDatabaseGuard.class)
class R06_RoleMembersConcurrencyIntegrationTest {
    private static final String ACTOR = "race-test";
    @Autowired RbacUseCase r;
    @Autowired JdbcTemplate db;
    @Autowired PlatformTransactionManager transactions;

    /**
     * A user who joins the role while a replacement is waiting for the role lock is only seen by the replacement's
     * locking read. Meanwhile a change to that user holds the user and waits for the replacement's assignment
     * locks; locking the user at that point would close a cycle, so the replacement starts over instead.
     */
    @DisplayName("R6 角色成员替换遇晚到成员回滚重排不发生死锁")
    @Test void aMemberWhoJoinsDuringAReplacementDoesNotDeadlockIt() throws Exception {
        String suffix = Credentials.token().substring(0, 12);
        long dept = -1, app = -1, stay = -1, late = -1;
        var pool = Executors.newFixedThreadPool(3);
        try {
            dept = r.department(new Requests.Department("Race Dept", "race-d-" + suffix), null, ACTOR);
            app = ((Number) r.application(new Requests.Application("Race App", "race-a-" + suffix, ""), ACTOR).get("id")).longValue();
            stay = r.user(new Requests.User("Stays", "race-stay-" + suffix, "", List.of(dept)), null, ACTOR);
            late = r.user(new Requests.User("Joins late", "race-late-" + suffix, "", List.of(dept)), null, ACTOR);
            long role = r.role(new Requests.Role("Race", "race", ""), null, dept, app, ACTOR);
            long d = dept, a = app, member = stay, joiner = late;
            var joined = new CountDownLatch(1);
            var commit = new CountDownLatch(1);
            var tx = new TransactionTemplate(transactions);
            Future<?> joining = pool.submit(() -> tx.executeWithoutResult(status -> {
                db.queryForObject("SELECT id FROM roles WHERE id=? FOR UPDATE", Long.class, role);
                db.update("INSERT INTO user_roles(user_id,role_id,department_id,application_id) VALUES (?,?,?,?)", joiner, role, d, a);
                joined.countDown();
                try { commit.await(30, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }));
            assertThat(joined.await(10, TimeUnit.SECONDS)).isTrue();
            Future<?> replacing = pool.submit(() -> r.roleMembers(role, d, a, List.of(member), ACTOR));
            Thread.sleep(500);
            Future<?> changing = pool.submit(() -> r.userRoles(joiner, d, a, List.of(role), ACTOR));
            Thread.sleep(500);
            assertThat(replacing.isDone()).as("the replacement waits for the role").isFalse();
            assertThat(changing.isDone()).as("the change to the late member waits for its assignments").isFalse();
            commit.countDown();
            joining.get(10, TimeUnit.SECONDS);
            changing.get(20, TimeUnit.SECONDS);
            replacing.get(20, TimeUnit.SECONDS);
            assertThat(db.queryForList("SELECT user_id FROM user_roles WHERE role_id=?", Long.class, role)).containsExactly(stay);
        } finally {
            pool.shutdownNow();
            db.update("DELETE FROM users WHERE id IN (?,?)", stay, late);
            if (app > 0) {
                db.update("DELETE FROM roles WHERE application_id=?", app);
                db.update("DELETE FROM applications WHERE id=?", app);
            }
            if (dept > 0) db.update("DELETE FROM departments WHERE id=?", dept);
            db.update("DELETE FROM audit_events WHERE actor=? OR application_id=?", ACTOR, app);
        }
    }
}
