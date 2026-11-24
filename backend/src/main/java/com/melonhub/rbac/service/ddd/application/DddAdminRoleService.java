package com.melonhub.rbac.service.ddd.application;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.AdminFunction;
import com.melonhub.rbac.security.AdminPrincipal;
import com.melonhub.rbac.service.ddd.domain.model.AdminRoleAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.AdminRoleRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.value.DomainException;
import com.melonhub.rbac.service.port.AdminRoleUseCase;
import com.melonhub.rbac.service.port.AuthUseCase;
import com.melonhub.rbac.service.port.RbacUseCase;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * DDD 应用服务：管理员功能清单与自定义管理员角色管理。
 * 所有角色变更不变量由 {@link AdminRoleAggregate} 守护，本层只协调锁、事务与仓储持久化。
 */
@Service
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class DddAdminRoleService implements AdminRoleUseCase {
    private static final Set<String> KNOWN_FUNCTIONS = Arrays.stream(AdminFunction.values())
            .map(AdminFunction::code).collect(Collectors.toUnmodifiableSet());
    private static final Set<String> PLATFORM_ADMIN_ONLY_FUNCTIONS = Arrays.stream(AdminFunction.values())
            .filter(AdminFunction::platformAdminOnly).map(AdminFunction::code).collect(Collectors.toUnmodifiableSet());

    private final AdminRoleRepositoryPort repository;
    private final RbacUseCase rbac;
    private final AuthUseCase accounts;

    public DddAdminRoleService(AdminRoleRepositoryPort repository, RbacUseCase rbac, AuthUseCase accounts) {
        this.repository = repository;
        this.rbac = rbac;
        this.accounts = accounts;
    }

    @Override
    public List<Map<String, Object>> functions() {
        return repository.functions();
    }

    @Override
    public List<Map<String, Object>> roles() {
        return repository.roles();
    }

    @Override
    @Transactional
    public void create(Requests.AdminRoleCreate input, AdminPrincipal actor) {
        DddBoundary.run(() -> {
            var aggregate = AdminRoleAggregate.createCustom(
                    input.code(), input.name(), input.description(), input.functions(),
                    KNOWN_FUNCTIONS, heldFunctionCodes(actor), PLATFORM_ADMIN_ONLY_FUNCTIONS);
            if (repository.roleExists(aggregate.code())) {
                throw DomainException.conflict("角色编码已存在");
            }
            repository.createRole(aggregate.code(), aggregate.name(), aggregate.description(), aggregate.functions());
            rbac.audit(actor.actor(), "ADMIN_ROLE_CREATED", aggregate.code(), null, null, aggregate.auditCreateDetail());
        });
    }

    @Override
    @Transactional
    public void update(String code, Requests.AdminRoleUpdate input, AdminPrincipal actor) {
        DddBoundary.run(() -> {
            accounts.lockTree();
            var existing = repository.findRole(code).orElseThrow(() -> DomainException.missing("管理员角色不存在"));
            var updated = existing.updateCustom(
                    input.name(), input.description(), input.functions(),
                    KNOWN_FUNCTIONS, heldFunctionCodes(actor), PLATFORM_ADMIN_ONLY_FUNCTIONS);
            accounts.requireConsistentWithRole(code, updated.functions());
            repository.updateRole(updated.code(), updated.name(), updated.description(), updated.functions());
            rbac.audit(actor.actor(), "ADMIN_ROLE_UPDATED", updated.code(), null, null, updated.auditUpdateDiffFrom(existing));
        });
    }

    @Override
    @Transactional
    public void delete(String code, AdminPrincipal actor) {
        DddBoundary.run(() -> {
            accounts.lockTree();
            var existing = repository.findRole(code).orElseThrow(() -> DomainException.missing("管理员角色不存在"));
            existing.assertDeletable(repository.countAccountsUsingRole(code));
            if (repository.deleteRole(code) == 0) {
                throw DomainException.missing("管理员角色不存在");
            }
            rbac.audit(actor.actor(), "ADMIN_ROLE_DELETED", code, null, null, existing.name());
        });
    }

    private static Set<String> heldFunctionCodes(AdminPrincipal actor) {
        return actor.functions().stream().map(AdminFunction::code).collect(Collectors.toSet());
    }
}
