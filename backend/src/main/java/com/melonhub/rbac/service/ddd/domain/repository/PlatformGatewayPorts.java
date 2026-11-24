package com.melonhub.rbac.service.ddd.domain.repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * 纯领域基础设施网关端口集合（缓存失效、上下文/密钥缓存、事件外盒、事务、加密、JWT 与 HTTP 投递）。
 */
public final class PlatformGatewayPorts {
    private PlatformGatewayPorts() {}

    public enum CacheLookupStatus { HIT, MISS, NONE, BYPASS }

    public record CacheLookup(CacheLookupStatus status, String meta, String payload, String storeKey) {}

    public interface CacheGateway {
        long DEFAULT_TTL_SECONDS = 60;

        String health();

        void touchUser(long userId);

        void touchApplication(long applicationId);

        void touchKeys(long applicationId);

        void touchDomain(long departmentId, long applicationId);

        CacheLookup lookupContext(String hash);

        void putContextAfterCommit(String hash, String metaJson, long ttlSeconds);

        void putContext(String hash, String metaJson, long ttlSeconds);

        void forgetContextAfterCommit(String hash);

        CacheLookup lookupApiKey(String hash);

        void putApiKey(String hash, String metaJson);

        void storePayload(String key, String value, long ttlSeconds);
    }

    public interface DomainEventPublisher {
        void emit(long applicationId, String type, Map<String, Object> data);

        void emitAll(String type, Map<String, Object> data);
    }

    public interface TransactionRunner {
        <T> T inTransaction(Supplier<T> work);

        <T> T inReadOnlyTransaction(Supplier<T> work);
    }

    public interface CryptoGateway {
        String encodeAdminPassword(String rawPassword);

        boolean matchesAdminPassword(String rawPassword, String encodedHash);

        void consumeDummyAdminCheck();

        String encodeIdentityPassword(String rawPassword);

        boolean matchesIdentityPassword(String rawPassword, String encodedHash);

        String generateToken();

        String generateApiKey();

        String apiKeyPrefix(String rawKey);

        String hashToken(String rawToken);

        String hashTokenOrNull(String rawToken);

        String generateTotpSecret();

        Long verifyTotp(String secret, String code);

        String currentClientAddress();
    }

    public interface IdentityTokenGateway {
        record VerifiedToken(String subject, List<String> audience, Instant issuedAt, Instant expiresAt, String tokenId) {}

        String issue(String subject, List<String> audience, Instant issuedAt);

        VerifiedToken verify(String token, String expectedAudience);
    }

    public interface JsonCodec {
        String write(Object value);

        <T> T readOrNull(String json, Class<T> type);
    }

    public interface WebhookTransport {
        int post(String url, String payload, String eventType, String eventId, String signatureHeader, int timeoutMillis) throws Exception;
    }
}
