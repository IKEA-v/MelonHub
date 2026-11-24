package com.melonhub.rbac.service.ddd.infrastructure;

import com.melonhub.rbac.dao.WebhookDao;
import com.melonhub.rbac.service.ddd.domain.model.WebhookEndpointAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.PageSlice;
import com.melonhub.rbac.service.ddd.domain.repository.WebhookRepositoryPort;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** DDD 基础设施适配器：将 {@link WebhookRepositoryPort} 桥接到 {@link WebhookDao}。 */
@Component
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class JpaWebhookRepositoryAdapter implements WebhookRepositoryPort {
    private final WebhookDao dao;

    public JpaWebhookRepositoryAdapter(WebhookDao dao) {
        this.dao = dao;
    }

    @Override public List<Map<String, Object>> webhooks(long applicationId) { return dao.webhooks(applicationId); }
    @Override public Optional<Map<String, Object>> webhookView(long id) { return dao.webhook(id); }

    @Override
    public Optional<WebhookEndpointAggregate> findWebhook(long id) {
        return dao.webhook(id).map(row -> {
            String rawEvents = (String) row.get("events");
            List<String> events = rawEvents == null || rawEvents.isBlank() ? List.of() : List.of(rawEvents.split(","));
            return new WebhookEndpointAggregate(
                    ((Number) row.get("id")).longValue(),
                    ((Number) row.get("applicationId")).longValue(),
                    (String) row.get("name"),
                    (String) row.get("url"),
                    Boolean.TRUE.equals(row.get("enabled")),
                    events);
        });
    }

    @Override public long createWebhook(long applicationId, String name, String url, String secret, String events, boolean enabled, String actor) {
        return dao.create(applicationId, name, url, secret, events, enabled, actor);
    }
    @Override public int updateWebhook(long id, String name, String url, String events, boolean enabled) { return dao.update(id, name, url, events, enabled); }
    @Override public void updateWebhookSecret(long id, String secret) { dao.updateSecret(id, secret); }
    @Override public void deleteWebhook(long id) { dao.delete(id); }
    @Override public PageSlice deliveries(long webhookId, int page, int size) {
        var p = dao.deliveries(webhookId, page, size);
        return new PageSlice(p.items(), p.total());
    }
    @Override public void enqueueTest(long webhookId, String payload) { dao.enqueueTest(webhookId, payload); }
    @Override public void emit(long applicationId, String eventType, String payload) { dao.emit(applicationId, eventType, payload); }
    @Override public void emitAll(String eventType, String payload) { dao.emitAll(eventType, payload); }
    @Override public void requeueStale(int maxAttempts) { dao.requeueStale(maxAttempts); }

    @Override
    public List<DueDelivery> dueDeliveries(int limit) {
        return dao.dueDeliveries(limit).stream()
                .map(row -> new DueDelivery(
                        ((Number) row.get("id")).longValue(),
                        ((Number) row.get("attempts")).intValue(),
                        (String) row.get("url"),
                        (String) row.get("secret"),
                        (String) row.get("eventType"),
                        (String) row.get("eventId"),
                        (String) row.get("payload")))
                .toList();
    }

    @Override public int claimDelivery(long id, int expectedAttempts) { return dao.claim(id, expectedAttempts); }
    @Override public void releaseDelivery(long id, int attempt) { dao.release(id, attempt); }
    @Override public void markDelivered(long id, int attempt, int httpStatus) { dao.delivered(id, attempt, httpStatus); }
    @Override public void scheduleRetry(long id, int attempt, int delayMinutes, Integer httpStatus, String error) {
        dao.retry(id, attempt, delayMinutes, httpStatus, error);
    }
    @Override public void markFailed(long id, int attempt, Integer httpStatus, String error) { dao.failed(id, attempt, httpStatus, error); }
    @Override public int purgeDeliveries(int days, int limit) { return dao.purge(days, limit); }
}
