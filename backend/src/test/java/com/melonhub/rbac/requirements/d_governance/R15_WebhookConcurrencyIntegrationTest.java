package com.melonhub.rbac.requirements.d_governance;

import static org.assertj.core.api.Assertions.assertThat;

import com.melonhub.rbac.CloudTestDatabaseGuard;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.service.port.RbacUseCase;
import com.melonhub.rbac.service.port.WebhookUseCase;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

/**
 * Real multi-connection concurrency test (no {@code @Transactional}) verifying parallel Webhook dispatch.
 * 对应需求：R15（见 doc/requirements.md）。
 */
@SpringBootTest
@ActiveProfiles("test")
@ContextConfiguration(initializers = CloudTestDatabaseGuard.class)
class R15_WebhookConcurrencyIntegrationTest {
    private static final String ACTOR = "race-test";
    @Autowired RbacUseCase r;
    @Autowired WebhookUseCase webhooks;
    @Autowired JdbcTemplate db;

    @DisplayName("R15 慢 Webhook 接收端既不阻塞调度线程也不互相阻塞")
    @Test void slowWebhookReceiversNeitherHoldTheSchedulerNorEachOther() throws Exception {
        int deliveries = 3;
        var received = new CountDownLatch(deliveries);
        var receivers = Executors.newFixedThreadPool(deliveries);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(receivers);
        server.createContext("/slow", exchange -> {
            try { Thread.sleep(1500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            received.countDown();
        });
        server.start();
        long app = -1;
        try {
            String suffix = Credentials.token().substring(0, 12);
            app = ((Number) r.application(new Requests.Application("Race App", "race-" + suffix, ""), ACTOR).get("id")).longValue();
            long hook = ((Number) webhooks.create(app, new Requests.Webhook("慢接收方", "http://127.0.0.1:" + server.getAddress().getPort() + "/slow",
                    null, List.of("*"), true), ACTOR).get("id")).longValue();
            for (int i = 0; i < deliveries; i++) webhooks.test(hook, ACTOR);
            long started = System.nanoTime();
            webhooks.scheduledDeliveries();
            long dispatchMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertThat(dispatchMillis).as("the scheduler thread only claims and hands over").isLessThan(1000);
            assertThat(received.await(10, TimeUnit.SECONDS)).isTrue();
            long allMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertThat(allMillis).as("deliveries run side by side, not one after another").isLessThan(deliveries * 1500L);
            long deadline = System.currentTimeMillis() + 5000;
            long delivered = 0;
            while (System.currentTimeMillis() < deadline) {
                delivered = db.queryForObject("SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id=? AND status='DELIVERED'", Long.class, hook);
                if (delivered == deliveries) break;
                Thread.sleep(100);
            }
            assertThat(delivered).isEqualTo(deliveries);
        } finally {
            server.stop(0);
            receivers.shutdownNow();
            if (app > 0) db.update("DELETE FROM applications WHERE id=?", app);
            db.update("DELETE FROM audit_events WHERE actor=? OR application_id=?", ACTOR, app);
        }
    }
}
