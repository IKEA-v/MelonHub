package com.melonhub.rbac.requirements.f_audit_guard;

import static org.assertj.core.api.Assertions.assertThat;

import com.melonhub.rbac.dao.AuditDao;
import com.melonhub.rbac.requirements.support.GovernanceIntegrationSupport;
import com.melonhub.rbac.service.port.AuditSealUseCase;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R21（见 doc/requirements.md）。 */
class R21_AuditHashChainIntegrationTest extends GovernanceIntegrationSupport {

    @DisplayName("R21 审计哈希链校验通过并可检出记录篡改")
    @Test void auditChainVerifiesAndDetectsTampering() {
        rbacAudit(0);
        long first = lastAuditId();
        rbacAudit(1);
        rbacAudit(2);
        sealer.sealNow();
        long from = sealSeq(first);
        var before = sealer.verify(from, 10_000);
        assertThat(before.get("ok")).isEqualTo(true);
        assertThat(before.get("complete")).isEqualTo(true);
        long tampered = lastAuditId();
        db.update("UPDATE audit_events SET detail='篡改内容' WHERE id=?", tampered);
        var after = sealer.verify(from, 10_000);
        assertThat(after.get("ok")).isEqualTo(false);
        assertThat(after.get("problem")).isEqualTo("MODIFIED");
        assertThat(((Number) after.get("brokenAt")).longValue()).isEqualTo(tampered);
    }

    @DisplayName("R21 晚提交小 ID 审计记录按封存序入链并检出链尾缺失")
    @Test void lateCommittedRowsJoinTheChainAndRemovedTailIsDetected() {
        sealer.sealNow();
        rbacAudit(0);
        long late = lastAuditId();
        rbacAudit(1);
        long sealedFirst = lastAuditId();
        // Stand in for a transaction that has not committed yet: its id exists, its row is not visible.
        var row = db.queryForMap("SELECT actor,action,target,detail,source_ip FROM audit_events WHERE id=?", late);
        db.update("DELETE FROM audit_events WHERE id=?", late);
        sealer.sealNow();
        db.update("INSERT INTO audit_events(id,actor,action,target,detail,source_ip) VALUES (?,?,?,?,?,?)",
                late, row.get("actor"), row.get("action"), row.get("target"), row.get("detail"), row.get("source_ip"));
        sealer.sealNow();
        long from = sealSeq(sealedFirst);
        assertThat(sealSeq(late)).as("late row is appended, not skipped").isEqualTo(from + 1);
        var whole = sealer.verify(from, 10_000);
        assertThat(whole.get("ok")).isEqualTo(true);
        assertThat(whole.get("checked")).isEqualTo(2L);
        assertThat(whole.get("complete")).isEqualTo(true);
        // Removing the newest sealed row leaves an intact but shorter chain; the recorded chain end exposes it.
        db.update("DELETE FROM audit_events WHERE id=?", late);
        var cut = sealer.verify(from, 10_000);
        assertThat(cut.get("ok")).isEqualTo(false);
        assertThat(cut.get("problem")).isEqualTo("TAIL_MISSING");
        db.update("DELETE FROM audit_events WHERE seal_seq IS NOT NULL");
        var emptied = sealer.verify(null, 10_000);
        assertThat(emptied.get("ok")).isEqualTo(false);
        assertThat(emptied.get("problem")).isEqualTo("TAIL_MISSING");
    }

    @DisplayName("R21 审计保留期按前缀清理更新锚点后剩余链仍可验通")
    @Test void retentionCleanupCutsAPrefixAndLeavesAVerifiableChain() {
        rbacAudit(0);
        rbacAudit(1);
        long kept = lastAuditId();
        rbacAudit(2);
        long newest = lastAuditId();
        sealer.sealNow();
        long keptSeq = sealSeq(kept);
        db.update("UPDATE audit_events SET created_at=TIMESTAMPADD(DAY,-200,CURRENT_TIMESTAMP) WHERE seal_seq<?", keptSeq);
        while (sealer.purge(180) == AuditSealUseCase.PURGE_BATCH) { /* drain */ }
        assertThat(db.queryForObject("SELECT COUNT(*) FROM audit_events WHERE seal_seq<?", Long.class, keptSeq)).isZero();
        assertThat(db.queryForObject("SELECT anchor_seq FROM audit_seal WHERE id=1", Long.class)).isEqualTo(keptSeq - 1);
        var result = sealer.verify(null, 10_000);
        assertThat(result.get("ok")).isEqualTo(true);
        assertThat(result.get("firstId")).isEqualTo(kept);
        // Even when everything is past retention the chain end is kept, so the end can still be checked.
        db.update("UPDATE audit_events SET created_at=TIMESTAMPADD(DAY,-200,CURRENT_TIMESTAMP) WHERE seal_seq IS NOT NULL");
        sealer.purge(180);
        assertThat(db.queryForObject("SELECT COUNT(*) FROM audit_events WHERE seal_seq IS NOT NULL", Long.class)).isEqualTo(1L);
        assertThat(db.queryForObject("SELECT seal_seq FROM audit_events WHERE id=?", Long.class, newest)).isNotNull();
    }

    @DisplayName("R21 v2 长度前缀规范化哈希可检出跨审计字段挪移文本")
    @Test void movingTextBetweenAuditFieldsIsDetected() {
        var original = new HashMap<String, Object>(Map.of("id", 1L, "actor", "left|mid", "action", "right", "target", "t", "detail", "", "source_ip", "", "ts", 0L));
        var shifted = new HashMap<>(original);
        shifted.put("actor", "left");
        shifted.put("action", "mid|right");
        // The original "|"-joined form cannot tell these rows apart; the length-prefixed form can.
        assertThat(AuditDao.canonicalV1(shifted)).isEqualTo(AuditDao.canonicalV1(original));
        assertThat(AuditDao.canonicalV2(1, shifted)).isNotEqualTo(AuditDao.canonicalV2(1, original));
        rbacAudit(0);
        long id = lastAuditId();
        db.update("UPDATE audit_events SET actor='left|mid',action='right' WHERE id=?", id);
        sealer.sealNow();
        long from = sealSeq(id);
        assertThat(sealer.verify(from, 10_000).get("ok")).isEqualTo(true);
        db.update("UPDATE audit_events SET actor='left',action='mid|right' WHERE id=?", id);
        var result = sealer.verify(from, 10_000);
        assertThat(result.get("ok")).isEqualTo(false);
        assertThat(result.get("problem")).isEqualTo("MODIFIED");
    }
}
