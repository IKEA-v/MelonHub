package com.melonhub.rbac.service.ddd.application;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.AdminFunction;
import com.melonhub.rbac.security.AdminPrincipal;
import com.melonhub.rbac.service.ddd.domain.model.IdentityAccountAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.IdentityRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.CryptoGateway;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.IdentityTokenGateway;
import com.melonhub.rbac.service.ddd.domain.value.CoursePermissionCatalog;
import com.melonhub.rbac.service.ddd.domain.value.DomainException;
import com.melonhub.rbac.service.ddd.domain.value.PasswordPolicy;
import com.melonhub.rbac.service.port.IdentityUseCase;
import com.melonhub.rbac.service.port.RbacUseCase;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * DDD 应用服务：课程管理系统统一身份认证、权限查询、组织查询与课程业务审计日志。
 * 所有认证/授权业务判定与审计投影均委托给 {@link IdentityAccountAggregate} 和 {@link CoursePermissionCatalog}。
 */
@Service
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class DddIdentityService implements IdentityUseCase {
    private final IdentityRepositoryPort repository;
    private final RbacUseCase rbacService;
    private final CryptoGateway crypto;
    private final IdentityTokenGateway tokens;

    public DddIdentityService(IdentityRepositoryPort repository, RbacUseCase rbacService,
                              CryptoGateway crypto, IdentityTokenGateway tokens) {
        this.repository = repository;
        this.rbacService = rbacService;
        this.crypto = crypto;
        this.tokens = tokens;
    }

    @Override
    @Transactional
    public Map<String, Object> login(String username, String password, List<String> systems) {
        return DddBoundary.execute(() -> {
            IdentityAccountAggregate.validateLoginSystems(systems);
            var credential = repository.findCredential(username)
                    .orElseThrow(() -> DomainException.unauthorized("UNAUTHORIZED", "账号或密码错误。"));
            if (!crypto.matchesIdentityPassword(password, credential.passwordHash())) {
                throw DomainException.unauthorized("UNAUTHORIZED", "账号或密码错误。");
            }
            Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            String token = tokens.issue(credential.username(), systems, issuedAt);
            var claims = tokens.verify(token, CoursePermissionCatalog.COURSE_SYSTEM);
            if (!repository.createSession(crypto.hashToken(token), credential, CoursePermissionCatalog.COURSE_SYSTEM, claims.expiresAt())) {
                throw DomainException.unauthorized("UNAUTHORIZED", "账号或密码错误。");
            }
            var response = new LinkedHashMap<String, Object>();
            response.put("accessToken", token);
            response.put("tokenType", "Bearer");
            response.put("expiresIn", claims.expiresAt().getEpochSecond() - issuedAt.getEpochSecond());
            return response;
        });
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> auditLogs(String authorization, String actor, Long actorId, String target,
                                         OffsetDateTime from, OffsetDateTime to, int page, int pageSize) {
        return DddBoundary.execute(() -> {
            var user = authenticatedUser(authorization);
            var departments = repository.permissionDepartments(user.id(), CoursePermissionCatalog.COURSE_SYSTEM,
                    CoursePermissionCatalog.PERMISSION_AUDIT_VIEW);
            IdentityAccountAggregate.requireCourseAuditDepartments(departments);
            var events = repository.courseAuditEvents(CoursePermissionCatalog.COURSE_SYSTEM, departments, actor, actorId, target,
                    from == null ? null : from.toInstant(), to == null ? null : to.toInstant(), page, pageSize);
            var actorIds = events.items().stream().map(IdentityAccountAggregate.CourseAuditRecord::actorId)
                    .filter(Objects::nonNull).distinct().toList();
            var roles = repository.auditActorRoles(actorIds, CoursePermissionCatalog.COURSE_SYSTEM, departments);
            var items = events.items().stream().map(row -> IdentityAccountAggregate.projectCourseAuditEvent(row, roles)).toList();
            return page(page, pageSize, events.total(), items);
        });
    }

    @Override
    @Transactional
    public void logout(String authorization) {
        DddBoundary.run(() -> {
            String token = IdentityAccountAggregate.extractBearerToken(authorization);
            tokens.verify(token, CoursePermissionCatalog.COURSE_SYSTEM);
            repository.revokeSession(crypto.hashToken(token), Instant.now());
        });
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> currentUser(String authorization) {
        return DddBoundary.execute(() -> loadAggregate(authenticatedUser(authorization)).profileView());
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> departments(String authorization, String keyword, Long parentId, int page, int pageSize) {
        return DddBoundary.execute(() -> {
            loadAggregate(authenticatedUser(authorization)).requireOrganizationReadAccess();
            var rows = repository.departments(keyword, parentId, page, pageSize);
            var items = new ArrayList<Map<String, Object>>();
            for (var row : rows) {
                var item = new LinkedHashMap<String, Object>();
                item.put("id", row.id());
                item.put("code", row.code());
                item.put("name", row.name());
                item.put("parentId", row.parentId());
                item.put("hasChildren", row.hasChildren());
                items.add(item);
            }
            return page(page, pageSize, repository.departmentCount(keyword, parentId), items);
        });
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> departmentUsers(String authorization, long departmentId, String keyword, int page, int pageSize) {
        return DddBoundary.execute(() -> {
            loadAggregate(authenticatedUser(authorization)).requireOrganizationReadAccess();
            if (!repository.departmentExists(departmentId)) {
                throw new DomainException(DomainException.Kind.NOT_FOUND, "IDENTITY_DEPARTMENT_NOT_FOUND",
                        "统一身份认证系统中没有找到该部门。");
            }
            var rows = repository.departmentUsers(departmentId, keyword, page, pageSize);
            var items = new ArrayList<Map<String, Object>>();
            for (var row : rows) {
                var item = new LinkedHashMap<String, Object>();
                item.put("userId", row.userId());
                item.put("no", row.no());
                item.put("name", row.name());
                item.put("departmentId", row.departmentId());
                item.put("departmentName", row.departmentName());
                items.add(item);
            }
            return page(page, pageSize, repository.departmentUserCount(departmentId, keyword), items);
        });
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> checkPermission(String authorization, String permission) {
        return DddBoundary.execute(() -> {
            var user = authenticatedUser(authorization);
            var aggregate = new IdentityAccountAggregate(user, List.of(),
                    repository.permissions(user.id(), CoursePermissionCatalog.COURSE_SYSTEM));
            var response = new LinkedHashMap<String, Object>();
            response.put("allowed", aggregate.hasUiPermission(permission));
            return response;
        });
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> checkApiPermission(String authorization, String operationId) {
        return DddBoundary.execute(() -> {
            var user = authenticatedUser(authorization);
            String required = CoursePermissionCatalog.requirePermissionForOperation(operationId);
            var aggregate = new IdentityAccountAggregate(user, List.of(),
                    repository.permissions(user.id(), CoursePermissionCatalog.COURSE_SYSTEM));
            var response = new LinkedHashMap<String, Object>();
            response.put("operationId", operationId);
            response.put("allowed", aggregate.hasUiPermission(required));
            return response;
        });
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> lookupUser(String authorization, String userId) {
        return DddBoundary.execute(() -> {
            loadAggregate(authenticatedUser(authorization)).requireUserLookupAccess();
            var user = repository.findUserByExternalId(userId)
                    .orElseThrow(() -> new DomainException(DomainException.Kind.NOT_FOUND, "IDENTITY_USER_NOT_FOUND",
                            "统一身份认证系统中没有找到该用户。"));
            var response = new LinkedHashMap<String, Object>();
            response.put("userId", user.externalId());
            response.put("no", user.externalId());
            response.put("name", user.name());
            return response;
        });
    }

    @Override
    @Transactional
    public long provisionUser(Requests.User body, String password, String actor) {
        return DddBoundary.execute(() -> {
            Long existingId = repository.findUserByExternalId(body.externalId())
                    .map(IdentityAccountAggregate.IdentityUser::id).orElse(null);
            long userId = rbacService.user(body, existingId, actor);
            savePassword(userId, body.externalId(), password, actor);
            return userId;
        });
    }

    @Override
    @Transactional
    public long createUser(Requests.UserCreate body, AdminPrincipal principal) {
        return DddBoundary.execute(() -> {
            if (body.identityPassword() != null && !principal.canUse(AdminFunction.USER_CREDENTIALS)) {
                throw DomainException.forbidden("当前账号没有管理用户登录凭据功能");
            }
            long userId = rbacService.user(body.profile(), null, principal.actor(), principal.visibleDepartments());
            if (body.identityPassword() != null) {
                savePassword(userId, body.externalId(), body.identityPassword(), principal.actor());
            }
            return userId;
        });
    }

    @Override
    @Transactional
    public void setUserPassword(long userId, String password, AdminPrincipal principal) {
        DddBoundary.run(() -> {
            String username = rbacService.lockOwnedUser(userId, principal.visibleDepartments());
            savePassword(userId, username, password, principal.actor());
        });
    }

    private void savePassword(long userId, String username, String password, String actor) {
        PasswordPolicy.validateIdentityPassword(password);
        repository.upsertCredential(userId, username, crypto.encodeIdentityPassword(password));
        repository.revokeUserSessions(userId);
        rbacService.audit(actor, "USER_IDENTITY_PASSWORD_SET", username, null, null, "统一身份会话已结束");
    }

    private IdentityAccountAggregate.IdentityUser authenticatedUser(String authorization) {
        String token = IdentityAccountAggregate.extractBearerToken(authorization);
        var claims = tokens.verify(token, CoursePermissionCatalog.COURSE_SYSTEM);
        if (!repository.hasActiveSession(crypto.hashToken(token), Instant.now())) {
            throw DomainException.unauthorized("UNAUTHORIZED", "请先登录或令牌已失效。");
        }
        return repository.findUserByExternalId(claims.subject())
                .orElseThrow(() -> DomainException.unauthorized("UNAUTHORIZED", "请先登录。"));
    }

    private IdentityAccountAggregate loadAggregate(IdentityAccountAggregate.IdentityUser user) {
        return new IdentityAccountAggregate(
                user,
                repository.roles(user.id(), CoursePermissionCatalog.COURSE_SYSTEM),
                repository.permissions(user.id(), CoursePermissionCatalog.COURSE_SYSTEM)
        );
    }

    private static Map<String, Object> page(int page, int pageSize, long total, List<Map<String, Object>> items) {
        var response = new LinkedHashMap<String, Object>();
        response.put("page", page);
        response.put("pageSize", pageSize);
        response.put("total", total);
        response.put("items", items);
        return response;
    }
}
