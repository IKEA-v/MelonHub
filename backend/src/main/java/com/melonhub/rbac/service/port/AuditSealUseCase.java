package com.melonhub.rbac.service.port;

import java.util.Map;

/**
 * 审计日志 SHA-256 哈希链封存、前缀保留期清理与链路完整性校验用例端口。
 */
public interface AuditSealUseCase {
    int PURGE_BATCH = 5000;

    void scheduledSeal();

    int sealNow();

    int purge(int days);

    Map<String, Object> verify(Long fromSeq, int limit);
}
