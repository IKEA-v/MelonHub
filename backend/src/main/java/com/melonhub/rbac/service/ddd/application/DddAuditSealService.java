package com.melonhub.rbac.service.ddd.application;

import com.melonhub.rbac.service.ddd.domain.model.AuditHashChainAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.AuditChainRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.TransactionRunner;
import com.melonhub.rbac.service.port.AuditSealUseCase;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * DDD 应用服务：审计日志哈希链封存、前缀裁剪与完整性校验。
 * 所有链哈希计算、前缀上界和断链/篡改/尾缺判定均由 {@link AuditHashChainAggregate} 领域聚合根执行。
 */
@Service
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class DddAuditSealService implements AuditSealUseCase {
    private static final Logger log = LoggerFactory.getLogger(DddAuditSealService.class);
    private static final int BATCH = 500;
    private static final int MAX_BATCHES = 40;

    private final AuditChainRepositoryPort repository;
    private final TransactionRunner transactions;
    private final boolean scheduled;

    public DddAuditSealService(AuditChainRepositoryPort repository, TransactionRunner transactions,
                               @Value("${melonhub.maintenance.enabled:true}") boolean scheduled) {
        this.repository = repository;
        this.transactions = transactions;
        this.scheduled = scheduled;
    }

    @Override
    @Scheduled(initialDelay = 15_000, fixedDelay = 10_000)
    public void scheduledSeal() {
        if (scheduled) sealNow();
    }

    @Override
    public int sealNow() {
        int total = 0;
        try {
            for (int i = 0; i < MAX_BATCHES; i++) {
                int sealed = transactions.inTransaction(this::sealBatch);
                total += sealed;
                if (sealed < BATCH) break;
            }
        } catch (DataAccessException e) {
            log.warn("Audit chain sealing skipped: {}", e.getClass().getSimpleName());
        }
        return total;
    }

    private int sealBatch() {
        var seal = repository.lockSeal();
        var chain = new AuditHashChainAggregate(seal);
        var rows = repository.findUnsealed(BATCH);
        String previous = seal.lastHash();
        long seq = seal.lastSeq();
        long lastId = seal.lastId();
        int sealed = 0;
        for (var row : rows) {
            String hash = chain.computeHash(previous, seq + 1, row);
            if (repository.sealEvent(row.id(), seq + 1, previous, hash) == 0) continue;
            seq++;
            previous = hash;
            lastId = row.id();
            sealed++;
        }
        if (sealed > 0) {
            repository.updateSealHead(lastId, seq, previous, sealed);
        }
        return rows.size();
    }

    @Override
    public int purge(int days) {
        return transactions.inTransaction(() -> {
            var seal = repository.lockSeal();
            var chain = new AuditHashChainAggregate(seal);
            long below = chain.purgeUpperBoundSeq(repository.findFirstSeqSinceDays(days).orElse(null));
            var end = repository.findPrefixEnd(below, PURGE_BATCH);
            if (end.isEmpty()) return 0;
            int removed = repository.deleteEventsThrough(end.get().seq());
            repository.updateAnchor(end.get());
            return removed;
        });
    }

    @Override
    public Map<String, Object> verify(Long fromSeq, int limit) {
        sealNow();
        return transactions.inReadOnlyTransaction(() -> {
            long start = fromSeq == null ? 0 : fromSeq;
            var seal = repository.readSeal();
            var chain = new AuditHashChainAggregate(seal);
            var rows = repository.findSealedSegment(start, seal.lastSeq(), limit);
            var before = start > 0 ? repository.findLinkBefore(start).orElse(null) : null;
            return chain.verifySegment(rows, before, limit, repository.sealStateView());
        });
    }
}
