package com.melonhub.rbac.service.ddd.domain.value;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * 审计哈希链规范化与 SHA-256 摘要值对象（与历史 v1 及长度前缀 v2 链格式逐字节一致）。
 */
public final class AuditCanonicalizer {
    public static final String GENESIS = "0".repeat(64);

    private AuditCanonicalizer() {}

    public static String canonicalV1(long id, String actor, String action, String target,
                                     Long departmentId, Long applicationId, String detail, String sourceIp, Long epochSeconds) {
        return id + "|" + actor + "|" + action + "|" + target + "|"
                + emptyIfNull(departmentId) + "|" + emptyIfNull(applicationId) + "|" + detail + "|"
                + sourceIp + "|" + epochSeconds;
    }

    public static String canonicalV2(long sealSeq, long id, String actor, String action, String target,
                                     Long departmentId, Long applicationId, String detail, String sourceIp, Long epochSeconds) {
        var text = new StringBuilder("v2");
        for (Object field : new Object[] { sealSeq, id, actor, action, target, departmentId,
                applicationId, detail, sourceIp, epochSeconds }) {
            if (field == null) {
                text.append("|-");
                continue;
            }
            String value = field.toString();
            text.append('|').append(value.length()).append(':').append(value);
        }
        return text.toString();
    }

    public static String chainHash(String prevHash, long sealSeq, long v2FromSeq, long id, String actor,
                                   String action, String target, Long departmentId, Long applicationId,
                                   String detail, String sourceIp, Long epochSeconds) {
        String body = sealSeq >= v2FromSeq
                ? canonicalV2(sealSeq, id, actor, action, target, departmentId, applicationId, detail, sourceIp, epochSeconds)
                : canonicalV1(id, actor, action, target, departmentId, applicationId, detail, sourceIp, epochSeconds);
        return sha256(prevHash + "|" + body);
    }

    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String emptyIfNull(Object column) {
        return column == null ? "" : column.toString();
    }
}
