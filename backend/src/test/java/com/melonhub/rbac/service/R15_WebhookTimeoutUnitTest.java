package com.melonhub.rbac.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.melonhub.rbac.cache.PermissionCache;
import com.melonhub.rbac.dao.RbacDao;
import com.melonhub.rbac.dao.WebhookDao;
import com.melonhub.rbac.identity.IdentityTokenService;
import com.melonhub.rbac.service.ddd.application.DddWebhookService;
import com.melonhub.rbac.service.ddd.infrastructure.JpaRbacRepositoryAdapter;
import com.melonhub.rbac.service.ddd.infrastructure.JpaWebhookRepositoryAdapter;
import com.melonhub.rbac.service.ddd.infrastructure.SpringPlatformGatewaysAdapter;
import com.melonhub.rbac.service.port.WebhookUseCase;
import com.melonhub.rbac.service.structured.StructuredWebhookService;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * 对应需求：R15（见 doc/requirements.md）。
 * 同时校验结构化与 DDD 双策略下 Webhook 请求超时覆盖含响应体读取的完整周期。
 */
class R15_WebhookTimeoutUnitTest {
    @ParameterizedTest(name = "[{0}]")
    @ValueSource(strings = { "structured", "ddd" })
    @DisplayName("R15 Webhook 请求超时覆盖含响应体读取的完整周期")
    void responseHeadersDoNotEndTheDeliveryDeadline(String strategy) throws Exception {
        var headers = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, 10);
            exchange.getResponseBody().write('x');
            exchange.getResponseBody().flush();
            headers.countDown();
            try { release.await(5, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            exchange.close();
        });
        server.start();
        var dao = mock(WebhookDao.class);
        when(dao.dueDeliveries(20)).thenReturn(List.of(Map.of("id", 1L, "attempts", 0, "payload", "{}", "secret", "test-secret",
                "eventType", "user.disabled", "eventId", "test", "url", "http://127.0.0.1:" + server.getAddress().getPort() + "/")));
        when(dao.claim(1L, 0)).thenReturn(1);
        WebhookUseCase service;
        if ("ddd".equals(strategy)) {
            var gateway = new SpringPlatformGatewaysAdapter(
                    mock(PermissionCache.class), mock(PlatformTransactionManager.class),
                    new BCryptPasswordEncoder(4),
                    new IdentityTokenService("unit-test-secret-unit-test-secret-32", "https://identity.test", 7200),
                    new ObjectMapper());
            service = new DddWebhookService(new JpaWebhookRepositoryAdapter(dao),
                    new JpaRbacRepositoryAdapter(mock(RbacDao.class)),
                    gateway, gateway, gateway, true, 500, 8, 1);
        } else {
            service = new StructuredWebhookService(dao, mock(RbacDao.class), new ObjectMapper(), true, 500, 8, 1);
        }
        try {
            long start = System.nanoTime();
            service.deliverNow();
            assertThat(headers.getCount()).isZero();
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(3));
            verify(dao).retry(1L, 1, 1, null, "TimeoutException");
            verify(dao, never()).delivered(anyLong(), anyInt(), anyInt());
        } finally {
            release.countDown();
            server.stop(0);
            service.stopSenders();
        }
    }
}
