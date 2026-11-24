package com.melonhub.rbac.service.ddd.infrastructure;

import com.melonhub.rbac.dao.IdentityDao;
import com.melonhub.rbac.service.ddd.domain.model.IdentityAccountAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.IdentityRepositoryPort;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** DDD 基础设施适配器：将 {@link IdentityRepositoryPort} 桥接到 {@link IdentityDao}。 */
@Component
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class JpaIdentityRepositoryAdapter implements IdentityRepositoryPort {
    private final IdentityDao dao;

    public JpaIdentityRepositoryAdapter(IdentityDao dao) {
        this.dao = dao;
    }

    @Override
    public Optional<IdentityAccountAggregate.IdentityCredentialSnapshot> findCredential(String username) {
        return dao.credential(username).map(c -> new IdentityAccountAggregate.IdentityCredentialSnapshot(
                c.userId(), c.username(), c.passwordHash()));
    }

    @Override
    public Optional<IdentityAccountAggregate.IdentityUser> findUserByExternalId(String externalId) {
        return dao.userByExternalId(externalId).map(u -> new IdentityAccountAggregate.IdentityUser(
                u.id(), u.externalId(), u.name()));
    }

    @Override
    public boolean createSession(String tokenHash, IdentityAccountAggregate.IdentityCredentialSnapshot credential,
                                 String systemCode, Instant expiresAt) {
        return dao.createSession(tokenHash,
                new IdentityDao.CredentialRow(credential.userId(), credential.username(), credential.passwordHash()),
                systemCode, expiresAt);
    }

    @Override public boolean hasActiveSession(String tokenHash, Instant now) { return dao.activeSession(tokenHash, now); }
    @Override public void revokeSession(String tokenHash, Instant now) { dao.revokeSession(tokenHash, now); }
    @Override public void upsertCredential(long userId, String username, String passwordHash) { dao.upsertCredential(userId, username, passwordHash); }
    @Override public void renameCredential(long userId, String newUsername) { dao.renameCredential(userId, newUsername); }
    @Override public void revokeUserSessions(long userId) { dao.revokeUserSessions(userId); }
    @Override public List<String> roles(long userId, String systemCode) { return dao.roles(userId, systemCode); }
    @Override public List<String> permissions(long userId, String systemCode) { return dao.permissions(userId, systemCode); }
    @Override public List<Long> permissionDepartments(long userId, String systemCode, String permissionCode) {
        return dao.permissionDepartments(userId, systemCode, permissionCode);
    }

    @Override
    public List<DepartmentRecord> departments(String keyword, Long parentId, int page, int pageSize) {
        return dao.departments(keyword, parentId, page, pageSize).stream()
                .map(d -> new DepartmentRecord(d.id(), d.code(), d.name(), d.parentId(), d.hasChildren()))
                .toList();
    }

    @Override public long departmentCount(String keyword, Long parentId) { return dao.departmentCount(keyword, parentId); }
    @Override public boolean departmentExists(long departmentId) { return dao.departmentExists(departmentId); }

    @Override
    public List<DepartmentUserRecord> departmentUsers(long departmentId, String keyword, int page, int pageSize) {
        return dao.departmentUsers(departmentId, keyword, page, pageSize).stream()
                .map(u -> new DepartmentUserRecord(u.userId(), u.no(), u.name(), u.departmentId(), u.departmentName()))
                .toList();
    }

    @Override public long departmentUserCount(long departmentId, String keyword) { return dao.departmentUserCount(departmentId, keyword); }

    @Override
    public CourseAuditPage courseAuditEvents(String systemCode, Collection<Long> departmentIds, String actor, Long actorId,
                                             String target, Instant from, Instant to, int page, int pageSize) {
        var result = dao.courseAuditEvents(systemCode, List.copyOf(departmentIds), actor, actorId, target, from, to, page, pageSize);
        var items = result.items().stream().map(row -> new IdentityAccountAggregate.CourseAuditRecord(
                ((Number) row.get("id")).longValue(),
                ((Timestamp) row.get("at")).toInstant(),
                (String) row.get("type"),
                (String) row.get("target"),
                (String) row.get("actorNo"),
                (Long) row.get("actorId"),
                (String) row.get("actorName")
        )).toList();
        return new CourseAuditPage(items, result.total());
    }

    @Override
    public Map<Long, List<String>> auditActorRoles(Collection<Long> actorIds, String systemCode, Collection<Long> departmentIds) {
        return dao.auditActorRoles(actorIds, systemCode, List.copyOf(departmentIds));
    }
}
