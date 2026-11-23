package com.melonhub.rbac.requirements.d_governance;

import static org.assertj.core.api.Assertions.assertThat;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.requirements.support.GovernanceIntegrationSupport;
import com.melonhub.rbac.service.WebhookService;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R15（见 doc/requirements.md）。 */
class R15_WebhookDeliveryIntegrationTest extends GovernanceIntegrationSupport {

    @DisplayName("R15 Webhook 投递带 HMAC 签名且失败后按退避重排")
    @Test void webhookDeliveryIsSignedAndFailuresAreRescheduled() throws Exception {
        var received = new CountDownLatch(1);
        var signature = new AtomicReference<String>();
        var body = new AtomicReference<String>();
        var event = new AtomicReference<String>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/hook", exchange -> {
            signature.set(exchange.getRequestHeaders().getFirst("MelonHub-Signature"));
            event.set(exchange.getRequestHeaders().getFirst("MelonHub-Event"));
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(200, 0);
            exchange.close();
            received.countDown();
        });
        server.start();
        try {
            String secret = "wh-test-secret-0123456789";
            webhooks.create(a1, new Requests.Webhook("测试钩子", "http://127.0.0.1:" + server.getAddress().getPort() + "/hook",
                    secret, List.of("user.roles.changed"), true), ACTOR);
            r.userRoles(u1, d1, a1, List.of(r1, r2), ACTOR);
            webhooks.deliverNow();
            assertThat(received.await(5, TimeUnit.SECONDS)).as("webhook delivered").isTrue();
            assertThat(event.get()).isEqualTo("user.roles.changed");
            String[] parts = signature.get().split(",");
            String timestamp = parts[0].substring(2);
            assertThat(parts[1].substring(3)).isEqualTo(WebhookService.hmacSha256(secret, timestamp + "." + body.get()));
            assertThat(mapper.readTree(body.get()).path("data").path("externalId").asText()).isEqualTo(external);
            Long deliveries = db.queryForObject("SELECT COUNT(*) FROM webhook_deliveries WHERE status='DELIVERED'", Long.class);
            assertThat(deliveries).isEqualTo(1);
        } finally {
            server.stop(0);
        }
        // A dead endpoint stays PENDING with backoff instead of being lost.
        webhooks.create(a1, new Requests.Webhook("不可用钩子", "http://127.0.0.1:1/hook", null, List.of("user.roles.changed"), true), ACTOR);
        r.userRoles(u1, d1, a1, List.of(r1), ACTOR);
        webhooks.deliverNow();
        var row = db.queryForMap("SELECT status,attempts,last_error FROM webhook_deliveries ORDER BY id DESC LIMIT 1");
        assertThat(row.get("status")).isEqualTo("PENDING");
        assertThat(((Number) row.get("attempts")).intValue()).isEqualTo(1);
        assertThat((String) row.get("last_error")).isNotBlank();
    }

    @DisplayName("R15 停用 Webhook 保留投递队列并在重启后继续发送")
    @Test void disabledWebhookKeepsItsQueueUntilEnabledAgain() {
        var hook = new Requests.Webhook("停用钩子", "http://127.0.0.1:1/hook", null, List.of("user.roles.changed"), true);
        long id = ((Number) webhooks.create(a1, hook, ACTOR).get("id")).longValue();
        r.userRoles(u1, d1, a1, List.of(r1, r2), ACTOR);
        webhooks.update(id, new Requests.Webhook(hook.name(), hook.url(), null, hook.events(), false), ACTOR);
        webhooks.deliverNow();
        var queued = db.queryForMap("SELECT status,attempts FROM webhook_deliveries WHERE webhook_id=?", id);
        assertThat(queued.get("status")).isEqualTo("PENDING");
        assertThat(((Number) queued.get("attempts")).intValue()).isZero();
        webhooks.update(id, hook, ACTOR);
        webhooks.deliverNow();
        assertThat(db.queryForObject("SELECT attempts FROM webhook_deliveries WHERE webhook_id=?", Integer.class, id)).isEqualTo(1);
    }

    @DisplayName("R15 租约过期的陈旧 Webhook 读取无法认领或覆写结果")
    @Test void staleWebhookReadsCannotClaimOrFinishADelivery() {
        long hook = ((Number) webhooks.create(a1, new Requests.Webhook("认领", "http://127.0.0.1:1/hook", null, List.of("user.roles.changed"), true), ACTOR)
                .get("id")).longValue();
        r.userRoles(u1, d1, a1, List.of(r1, r2), ACTOR);
        long delivery = db.queryForObject("SELECT id FROM webhook_deliveries WHERE webhook_id=?", Long.class, hook);
        assertThat(webhookDao.claim(delivery, 1)).as("attempt count differs from the read").isZero();
        db.update("UPDATE webhook_deliveries SET next_attempt_at=TIMESTAMPADD(MINUTE,5,CURRENT_TIMESTAMP) WHERE id=?", delivery);
        assertThat(webhookDao.claim(delivery, 0)).as("not due yet").isZero();
        db.update("UPDATE webhook_deliveries SET next_attempt_at=TIMESTAMPADD(SECOND,-1,CURRENT_TIMESTAMP) WHERE id=?", delivery);
        assertThat(webhookDao.claim(delivery, 0)).isEqualTo(1);
        assertThat(webhookDao.claim(delivery, 0)).isZero();
        // The first worker's lease lapses and another worker claims the delivery again.
        db.update("UPDATE webhook_deliveries SET next_attempt_at=TIMESTAMPADD(SECOND,-1,CURRENT_TIMESTAMP) WHERE id=?", delivery);
        webhookDao.requeueStale(8);
        assertThat(webhookDao.claim(delivery, 1)).isEqualTo(1);
        assertThat(webhookDao.delivered(delivery, 1, 200)).as("the lapsed claim cannot write its result").isZero();
        assertThat(webhookDao.delivered(delivery, 2, 200)).isEqualTo(1);
    }

    @DisplayName("R15 Webhook 列表返回数组契约且权限变更触发通知")
    @Test void webhookListReturnsArraysAndPermissionMutationsAreAnnounced() {
        long hook = requestId(webhooks.create(a1, new Requests.Webhook("变更", "http://127.0.0.1:1/hook", null, List.of("*"), true), ACTOR));
        assertThat(webhooks.webhooks(a1).get(0).get("events")).isEqualTo(List.of("*"));
        webhooks.update(hook, new Requests.Webhook("变更", "http://127.0.0.1:1/hook", null, List.of("permission.updated", "permission.deleted", "role.enabled", "role.deleted", "user.contexts.revoked"), true), ACTOR);
        assertThat((List<?>) webhooks.webhooks(a1).get(0).get("events")).hasSize(5);
        long permission = db.queryForObject("SELECT id FROM permissions WHERE department_id=? AND application_id=? AND code='item:write'", Long.class, d1, a1);
        r.permission(new Requests.Permission("Write", "item:edit", "item", "edit"), permission, d1, a1, ACTOR);
        r.deletePermission(permission, d1, a1, ACTOR);
        r.roleStatus(r2, d1, a1, true, ACTOR);
        r.deleteRole(r2, d1, a1, ACTOR);
        r.revokeUserContexts(u1, ACTOR, null);
        assertThat(db.queryForList("SELECT event_type FROM webhook_deliveries WHERE webhook_id=? ORDER BY id", String.class, hook))
                .containsExactly("permission.updated", "permission.deleted", "role.enabled", "role.deleted", "user.contexts.revoked");
    }
}
