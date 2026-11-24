package com.melonhub.rbac.service.ddd.infrastructure;

import com.melonhub.rbac.dao.AuditDao;
import com.melonhub.rbac.service.ddd.domain.model.AuditHashChainAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.AuditChainRepositoryPort;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** DDD 基础设施适配器：将 {@link AuditChainRepositoryPort} 桥接到 {@link AuditDao}。 */
@Component
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class JpaAuditChainRepositoryAdapter implements AuditChainRepositoryPort {
    private final AuditDao dao;

    public JpaAuditChainRepositoryAdapter(AuditDao dao) {
        this.dao = dao;
    }

    @Override public AuditHashChainAggregate.SealMetadata lockSeal() { return toSeal(dao.lockSeal()); }
    @Override public AuditHashChainAggregate.SealMetadata readSeal() { return toSeal(dao.seal()); }
    @Override public List<AuditHashChainAggregate.AuditEventData> findUnsealed(int limit) {
        return dao.unsealed(limit).stream().map(JpaAuditChainRepositoryAdapter::toEvent).toList();
    }
    @Override public int sealEvent(long id, long sealSeq, String prevHash, String chainHash) { return dao.sealEvent(id, sealSeq, prevHash, chainHash); }
    @Override public void updateSealHead(long lastId, long lastSeq, String lastHash, long sealedCount) { dao.updateSeal(lastId, lastSeq, lastHash, sealedCount); }
    @Override public List<AuditHashChainAggregate.AuditEventData> findSealedSegment(long fromSeq, long toSeq, int limit) {
        return dao.sealedFrom(fromSeq, toSeq, limit).stream().map(JpaAuditChainRepositoryAdapter::toEvent).toList();
    }
    @Override public Optional<AuditHashChainAggregate.ChainLink> findLinkBefore(long seq) {
        return dao.linkBefore(seq).map(l -> new AuditHashChainAggregate.ChainLink(l.seq(), l.hash()));
    }
    @Override public Optional<Long> findFirstSeqSinceDays(int days) { return dao.firstSeqSince(days); }
    @Override public Optional<AuditHashChainAggregate.ChainLink> findPrefixEnd(long belowSeq, int limit) {
        return dao.prefixEnd(belowSeq, limit).map(l -> new AuditHashChainAggregate.ChainLink(l.seq(), l.hash()));
    }
    @Override public int deleteEventsThrough(long seq) { return dao.deleteThrough(seq); }
    @Override public void updateAnchor(AuditHashChainAggregate.ChainLink anchor) { dao.updateAnchor(new AuditDao.Link(anchor.seq(), anchor.hash())); }
    @Override public Map<String, Object> sealStateView() { return dao.sealState(); }

    private static AuditHashChainAggregate.SealMetadata toSeal(AuditDao.SealRow row) {
        return new AuditHashChainAggregate.SealMetadata(row.lastId(), row.lastSeq(), row.lastHash(),
                row.anchorSeq(), row.anchorHash(), row.v2FromSeq());
    }

    private static AuditHashChainAggregate.AuditEventData toEvent(Map<String, Object> row) {
        return new AuditHashChainAggregate.AuditEventData(
                ((Number) row.get("id")).longValue(),
                (String) row.get("actor"),
                (String) row.get("action"),
                (String) row.get("target"),
                nullableLong(row.get("department_id")),
                nullableLong(row.get("application_id")),
                (String) row.get("detail"),
                (String) row.get("source_ip"),
                nullableLong(row.get("ts")),
                nullableLong(row.get("seal_seq")),
                (String) row.get("prev_hash"),
                (String) row.get("chain_hash")
        );
    }

    private static Long nullableLong(Object value) { return value == null ? null : ((Number) value).longValue(); }
}
