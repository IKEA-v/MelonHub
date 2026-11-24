package com.melonhub.rbac.service.ddd.domain.repository;

import com.melonhub.rbac.service.ddd.domain.model.PermissionContextAggregate;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 权限上下文限界上下文的领域仓储端口。
 */
public interface PermissionContextRepositoryPort {
    record LockedUserContextRow(long userId, boolean enabled, Long activeDepartmentId, long contextVersion) {}

    record StoredContextState(long userId, long departmentId, long applicationId, long contextVersion, Instant expiresAt, boolean valid) {}

    Optional<LockedUserContextRow> lockUserByExternalId(String externalId);

    boolean isApplicationEnabled(long applicationId);

    boolean isMember(long userId, long departmentId);

    List<Long> assignedRoleIds(long userId, long departmentId, long applicationId);

    void switchDepartment(long userId, long departmentId, long newVersion);

    void clearStaleContexts(long userId, long version);

    void createContext(String tokenHash, long userId, long departmentId, long applicationId, long version, Instant expiresAt);

    void activateRoles(String tokenHash, Collection<Long> roleIds);

    Optional<StoredContextState> contextState(String tokenHash);

    List<PermissionContextAggregate.EffectiveRole> effectiveRoles(long userId, String tokenHash, long departmentId, long applicationId);

    List<String> effectivePermissions(long userId, String tokenHash, long departmentId, long applicationId);

    void revokeByHash(String tokenHash, long applicationId);

    List<Map<String, Object>> activeContexts(long userId);

    int revokeUser(long userId);

    void revokeDomain(long userId, long departmentId, long applicationId);

    void revokeDomainForUsers(Collection<Long> userIds, long departmentId, long applicationId);

    void revokeApplication(long applicationId);

    void revokeDepartment(long departmentId);

    int purgeExpired(int limit);
}
