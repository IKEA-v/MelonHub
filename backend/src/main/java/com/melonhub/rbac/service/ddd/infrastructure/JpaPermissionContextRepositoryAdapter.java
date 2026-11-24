package com.melonhub.rbac.service.ddd.infrastructure;

import com.melonhub.rbac.dao.ContextDao;
import com.melonhub.rbac.service.ddd.domain.model.PermissionContextAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.PermissionContextRepositoryPort;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** DDD 基础设施适配器：将 {@link PermissionContextRepositoryPort} 桥接到 {@link ContextDao}。 */
@Component
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class JpaPermissionContextRepositoryAdapter implements PermissionContextRepositoryPort {
    private final ContextDao dao;

    public JpaPermissionContextRepositoryAdapter(ContextDao dao) {
        this.dao = dao;
    }

    @Override
    public Optional<LockedUserContextRow> lockUserByExternalId(String externalId) {
        var found = dao.lockUserByExternalId(externalId);
        if (found.isEmpty()) return Optional.empty();
        var row = found.get(0);
        Object active = row.get("active_department_id");
        return Optional.of(new LockedUserContextRow(
                ((Number) row.get("id")).longValue(),
                Boolean.TRUE.equals(row.get("enabled")),
                active == null ? null : ((Number) active).longValue(),
                ((Number) row.get("context_version")).longValue()
        ));
    }

    @Override public boolean isApplicationEnabled(long applicationId) { return dao.applicationEnabled(applicationId); }
    @Override public boolean isMember(long userId, long departmentId) { return dao.member(userId, departmentId); }
    @Override public List<Long> assignedRoleIds(long userId, long departmentId, long applicationId) { return dao.assignedRoles(userId, departmentId, applicationId); }
    @Override public void switchDepartment(long userId, long departmentId, long newVersion) { dao.switchDepartment(userId, departmentId, newVersion); }
    @Override public void clearStaleContexts(long userId, long version) { dao.clearStaleContexts(userId, version); }
    @Override public void createContext(String tokenHash, long userId, long departmentId, long applicationId, long version, Instant expiresAt) {
        dao.create(tokenHash, userId, departmentId, applicationId, version, expiresAt);
    }
    @Override public void activateRoles(String tokenHash, Collection<Long> roleIds) { dao.activateRoles(tokenHash, roleIds); }
    @Override public Optional<StoredContextState> contextState(String tokenHash) {
        return dao.state(tokenHash).map(s -> new StoredContextState(
                s.context().user(), s.context().department(), s.context().application(),
                s.context().version(), s.context().expiresAt(), s.valid()));
    }
    @Override public List<PermissionContextAggregate.EffectiveRole> effectiveRoles(long userId, String tokenHash, long departmentId, long applicationId) {
        return dao.effectiveRoles(userId, tokenHash, departmentId, applicationId).stream()
                .map(r -> new PermissionContextAggregate.EffectiveRole(
                        ((Number) r.get("id")).longValue(),
                        (String) r.get("name"),
                        (String) r.get("code"),
                        r.get("expires_at") instanceof Timestamp ts ? ts.toInstant() : null))
                .toList();
    }
    @Override public List<String> effectivePermissions(long userId, String tokenHash, long departmentId, long applicationId) {
        return dao.effectivePermissions(userId, tokenHash, departmentId, applicationId);
    }
    @Override public void revokeByHash(String tokenHash, long applicationId) { dao.revoke(tokenHash, applicationId); }
    @Override public List<Map<String, Object>> activeContexts(long userId) { return dao.activeContexts(userId); }
    @Override public int revokeUser(long userId) { return dao.revokeUser(userId); }
    @Override public void revokeDomain(long userId, long departmentId, long applicationId) { dao.revokeDomain(userId, departmentId, applicationId); }
    @Override public void revokeDomainForUsers(Collection<Long> userIds, long departmentId, long applicationId) { dao.revokeDomain(userIds, departmentId, applicationId); }
    @Override public void revokeApplication(long applicationId) { dao.clearApplication(applicationId); }
    @Override public void revokeDepartment(long departmentId) { dao.clearDepartment(departmentId); }
    @Override public int purgeExpired(int limit) { return dao.purgeExpired(limit); }
}
