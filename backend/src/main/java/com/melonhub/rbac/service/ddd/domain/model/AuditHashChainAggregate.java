package com.melonhub.rbac.service.ddd.domain.model;

import com.melonhub.rbac.service.ddd.domain.value.AuditCanonicalizer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 审计哈希链聚合根：封装按封存序连续计算 SHA-256 链哈希、前缀裁剪边界以及链路篡改/断链/尾缺检测状态机。
 */
public final class AuditHashChainAggregate {
    public record SealMetadata(long lastId, long lastSeq, String lastHash, long anchorSeq, String anchorHash, long v2FromSeq) {}

    public record ChainLink(long seq, String hash) {}

    public record AuditEventData(
            long id,
            String actor,
            String action,
            String target,
            Long departmentId,
            Long applicationId,
            String detail,
            String sourceIp,
            Long epochSeconds,
            Long sealSeq,
            String prevHash,
            String chainHash
    ) {}

    private final SealMetadata seal;

    public AuditHashChainAggregate(SealMetadata seal) {
        this.seal = seal;
    }

    public String computeHash(String previousHash, long sequence, AuditEventData event) {
        return AuditCanonicalizer.chainHash(previousHash, sequence, seal.v2FromSeq(),
                event.id(), event.actor(), event.action(), event.target(),
                event.departmentId(), event.applicationId(), event.detail(), event.sourceIp(), event.epochSeconds());
    }

    public long purgeUpperBoundSeq(Long firstSeqWithinRetention) {
        return firstSeqWithinRetention == null ? seal.lastSeq() : Math.min(firstSeqWithinRetention, seal.lastSeq());
    }

    public Map<String, Object> verifySegment(List<AuditEventData> rows, ChainLink previousLink, int limit, Map<String, Object> sealStateView) {
        String expected = previousLink != null ? previousLink.hash() : seal.anchorHash();
        long seen = previousLink != null ? previousLink.seq() : seal.anchorSeq();
        long checked = 0, firstId = -1, lastId = -1, firstSeq = -1, brokenAt = -1, brokenSeq = -1;
        String problem = null;
        for (var row : rows) {
            long id = row.id();
            long seq = row.sealSeq();
            if (!AuditCanonicalizer.constantTimeEquals(row.prevHash(), expected)) {
                problem = "LINK_BROKEN";
            } else if (!AuditCanonicalizer.constantTimeEquals(row.chainHash(), computeHash(row.prevHash(), seq, row))) {
                problem = "MODIFIED";
            }
            if (problem != null) {
                brokenAt = id;
                brokenSeq = seq;
                break;
            }
            expected = row.chainHash();
            seen = seq;
            if (firstId < 0) {
                firstId = id;
                firstSeq = seq;
            }
            lastId = id;
            checked++;
        }
        boolean complete = problem == null && (rows.size() < limit || seen >= seal.lastSeq());
        if (complete && (seen != seal.lastSeq() || !AuditCanonicalizer.constantTimeEquals(expected, seal.lastHash()))) {
            problem = "TAIL_MISSING";
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("ok", problem == null);
        result.put("problem", problem);
        result.put("checked", checked);
        result.put("firstSeq", firstSeq < 0 ? null : firstSeq);
        result.put("lastSeq", checked == 0 ? null : seen);
        result.put("firstId", firstId < 0 ? null : firstId);
        result.put("lastId", lastId < 0 ? null : lastId);
        result.put("brokenAt", brokenAt < 0 ? null : brokenAt);
        result.put("brokenSeq", brokenSeq < 0 ? null : brokenSeq);
        result.put("complete", complete);
        result.put("nextSeq", problem == null && !complete ? seen + 1 : null);
        result.put("seal", sealStateView);
        return result;
    }
}
