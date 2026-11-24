package com.melonhub.rbac.service.ddd.domain.model;

import com.melonhub.rbac.service.ddd.domain.value.DomainException;
import com.melonhub.rbac.service.ddd.domain.value.WebhookSignature;
import java.util.List;

/**
 * Webhook 订阅与投递聚合根：守护事件订阅白名单、停用订阅拒绝测试、以及投递结果的重试/终态状态机。
 */
public final class WebhookEndpointAggregate {
    public enum DeliveryOutcomeType {
        DELIVERED,
        RETRY,
        FAILED
    }

    public record DeliveryDecision(DeliveryOutcomeType type, int delayMinutes, Integer httpStatus, String error) {}

    private final long id;
    private final long applicationId;
    private final String name;
    private final String url;
    private final boolean enabled;
    private final List<String> events;

    public WebhookEndpointAggregate(long id, long applicationId, String name, String url, boolean enabled, List<String> events) {
        this.id = id;
        this.applicationId = applicationId;
        this.name = name;
        this.url = url;
        this.enabled = enabled;
        this.events = List.copyOf(events);
    }

    public long id() { return id; }
    public long applicationId() { return applicationId; }
    public String name() { return name; }
    public String url() { return url; }
    public boolean enabled() { return enabled; }
    public List<String> events() { return events; }

    public static String validateAndJoinEvents(List<String> events) {
        return WebhookSignature.joinValidatedEvents(events);
    }

    public void assertTestAllowed() {
        if (!enabled) {
            throw DomainException.conflict("Webhook 已停用，请先启用");
        }
    }

    public static DeliveryDecision decideOnHttpStatus(int attempt, int maxAttempts, int statusCode) {
        if (statusCode >= 200 && statusCode < 300) {
            return new DeliveryDecision(DeliveryOutcomeType.DELIVERED, 0, statusCode, null);
        }
        return decideOnFailure(attempt, maxAttempts, statusCode, "HTTP " + statusCode);
    }

    public static DeliveryDecision decideOnFailure(int attempt, int maxAttempts, Integer statusCode, String error) {
        if (attempt >= maxAttempts) {
            return new DeliveryDecision(DeliveryOutcomeType.FAILED, 0, statusCode, error);
        }
        return new DeliveryDecision(DeliveryOutcomeType.RETRY, WebhookSignature.backoffMinutes(attempt), statusCode, error);
    }
}
