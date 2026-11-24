package com.melonhub.rbac.service.ddd.infrastructure;

import com.melonhub.rbac.dao.AuthDao;
import com.melonhub.rbac.service.ddd.domain.model.AdminCredentialAccount;
import com.melonhub.rbac.service.ddd.domain.model.AdminHierarchy;
import com.melonhub.rbac.service.ddd.domain.repository.AdminAccountRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.value.AdminScope;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** DDD 基础设施适配器：将 {@link AdminAccountRepositoryPort} 桥接到 {@link AuthDao}。 */
@Component
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class JpaAdminAccountRepositoryAdapter implements AdminAccountRepositoryPort {
    private final AuthDao dao;

    public JpaAdminAccountRepositoryAdapter(AuthDao dao) {
        this.dao = dao;
    }

    @Override public boolean accountExists(String username) { return dao.accountExists(username); }
    @Override public long createAccount(String username, String displayName, String role, String passwordHash, boolean enabled,
                                        Long parentId, String kind, boolean allDepartments, boolean allApplications) {
        return dao.createAccount(username, displayName, role, passwordHash, enabled, parentId, kind, allDepartments, allApplications);
    }
    @Override public void resetBootstrap(String username, String passwordHash, String superAdminRole) { dao.resetBootstrap(username, passwordHash, superAdminRole); }
    @Override public Optional<AdminCredentialAccount> findAccountByUsername(String username) { return dao.account(username).map(this::toAccount); }
    @Override public Optional<AdminCredentialAccount> findAccountById(long id) { return dao.account(id).map(this::toAccount); }
    @Override public boolean recordFailure(long id, int maxFailures, int lockMinutes) { return dao.recordFailure(id, maxFailures, lockMinutes); }
    @Override public void recordSuccess(long id) { dao.recordSuccess(id); }
    @Override public int createSession(String tokenHash, AdminCredentialAccount account, Instant expiresAt, String sourceIp) {
        var row = new AuthDao.AccountRow(account.id(), account.username(), account.displayName(), account.role(),
                account.enabled(), account.passwordHash(), account.locked(), account.mfaSecret(), account.mfaLastStep(),
                account.credentialVersion(), account.scope().allApplications(), account.kind(), account.root(),
                account.scope().allDepartments());
        return dao.createSession(tokenHash, row, expiresAt, sourceIp);
    }
    @Override public Optional<SessionSnapshot> findActiveSession(String tokenHash, int idleMinutes) {
        return dao.session(tokenHash, idleMinutes).map(s -> new SessionSnapshot(
                s.id(), s.username(), s.displayName(), s.role(), s.allApplications(),
                s.kind(), s.root(), s.allDepartments(), s.stale()));
    }
    @Override public void touchSession(String tokenHash) { dao.touchSession(tokenHash); }
    @Override public void deleteSession(String tokenHash) { dao.logout(tokenHash); }
    @Override public void endAllSessions(long accountId) { dao.endSessions(accountId); }
    @Override public void keepOnlySession(long accountId, String tokenHash) { dao.keepOnlySession(accountId, tokenHash); }
    @Override public int replacePassword(long accountId, String expectedHash, String newHash) { return dao.replacePassword(accountId, expectedHash, newHash); }
    @Override public int updatePassword(long accountId, String newHash) { return dao.updatePassword(accountId, newHash); }
    @Override public void setMfaPendingSecret(long accountId, String secret) { dao.setMfaPending(accountId, secret); }
    @Override public String findMfaPendingSecret(long accountId) { return dao.pendingMfaSecret(accountId); }
    @Override public int confirmMfa(long accountId, String expectedPending, long step) { return dao.confirmMfa(accountId, expectedPending, step); }
    @Override public int consumeMfaStep(long accountId, String expectedSecret, long step) { return dao.consumeMfaStep(accountId, expectedSecret, step); }
    @Override public int disableMfaWithStep(long accountId, String expectedSecret, long step) { return dao.disableMfaWithStep(accountId, expectedSecret, step); }
    @Override public int disableMfa(long accountId) { return dao.disableMfa(accountId); }
    @Override public Optional<ApiKeySnapshot> findApiKeyByHash(String keyHash) {
        return dao.applicationKey(keyHash).map(k -> new ApiKeySnapshot(k.keyId(), k.applicationId(), k.valid(), k.expiresAt()));
    }
    @Override public void markKeysUsed(Collection<Long> keyIds) { dao.markKeysUsed(keyIds); }
    @Override public int purgeSessions(int idleMinutes, int limit) { return dao.purgeSessions(idleMinutes, limit); }
    @Override public void lockAllAccounts() { dao.lockAccounts(); }
    @Override public List<AdminHierarchy.AdminNode> loadHierarchyNodes() {
        return dao.nodes().stream()
                .map(n -> new AdminHierarchy.AdminNode(n.id(), n.username(), n.parentId(), n.kind(), n.role(), n.enabled(),
                        new AdminScope(n.allDepartments(), n.departments(), n.allApplications(), n.applications())))
                .toList();
    }
    @Override public List<Map<String, Object>> listAccountRows() { return dao.accounts(); }
    @Override public List<Map<String, Object>> accountApplicationPairs() { return dao.accountApplicationPairs(); }
    @Override public List<Map<String, Object>> accountDepartmentPairs() { return dao.accountDepartmentPairs(); }
    @Override public List<Long> accountApplications(long accountId) { return dao.accountApplications(accountId); }
    @Override public List<Long> accountDepartments(long accountId) { return dao.accountDepartments(accountId); }
    @Override public long countExistingApplications(Collection<Long> ids) { return dao.existingApplications(ids); }
    @Override public long countExistingDepartments(Collection<Long> ids) { return dao.existingDepartments(ids); }
    @Override public void replaceAccountApplications(long accountId, Collection<Long> applicationIds) { dao.replaceAccountApplications(accountId, applicationIds); }
    @Override public void replaceAccountDepartments(long accountId, Collection<Long> departmentIds) { dao.replaceAccountDepartments(accountId, departmentIds); }
    @Override public void updateAccount(long id, String displayName, String role, boolean enabled, String kind, boolean allDepartments, boolean allApplications) {
        dao.updateAccount(id, displayName, role, enabled, kind, allDepartments, allApplications);
    }
    @Override public void moveAccountUnder(long id, long parentId) { dao.moveUnder(id, parentId); }
    @Override public int unlockAccount(long id) { return dao.unlock(id); }
    @Override public int deleteAccount(long id) { return dao.deleteAccount(id); }

    private AdminCredentialAccount toAccount(AuthDao.AccountRow row) {
        return new AdminCredentialAccount(
                row.id(), row.username(), row.displayName(), row.role(), row.enabled(), row.passwordHash(),
                row.locked(), row.mfaSecret(), row.mfaLastStep(), row.credentialVersion(), row.kind(), row.root(),
                new AdminScope(row.allDepartments(), Set.of(), row.allApplications(), Set.of()));
    }
}
