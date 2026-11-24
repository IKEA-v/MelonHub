package com.melonhub.rbac.service.ddd.application;

import com.melonhub.rbac.dao.Visibility;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.service.ddd.domain.model.AccessRequestAggregate;
import com.melonhub.rbac.service.ddd.domain.model.AccessReviewAggregate;
import com.melonhub.rbac.service.ddd.domain.model.DomainAuthorizationAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.GovernanceRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.repository.PermissionContextRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.CacheGateway;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.DomainEventPublisher;
import com.melonhub.rbac.service.ddd.domain.repository.RbacRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.value.DomainException;
import com.melonhub.rbac.service.ddd.domain.value.IsolationDomain;
import com.melonhub.rbac.service.port.GovernanceUseCase;
import com.melonhub.rbac.service.port.RbacUseCase;
import jakarta.validation.Validator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * DDD 应用服务：授权治理（角色申请审批、定期权限复核、分配到期清理、批量导入、清单同步与反查报表）。
 * 核心状态机与校验规则由 {@link AccessRequestAggregate} 与 {@link AccessReviewAggregate} 聚合根守护。
 */
@Service
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class DddGovernanceService implements GovernanceUseCase {
    private final GovernanceRepositoryPort governance;
    private final RbacRepositoryPort rbacRepo;
    private final PermissionContextRepositoryPort contexts;
    private final CacheGateway cache;
    private final RbacUseCase rbac;
    private final DomainEventPublisher events;
    private final Validator validator;

    public DddGovernanceService(GovernanceRepositoryPort governance, RbacRepositoryPort rbacRepo,
                                PermissionContextRepositoryPort contexts, CacheGateway cache,
                                RbacUseCase rbac, DomainEventPublisher events, Validator validator) {
        this.governance = governance;
        this.rbacRepo = rbacRepo;
        this.contexts = contexts;
        this.cache = cache;
        this.rbac = rbac;
        this.events = events;
        this.validator = validator;
    }

    @Override
    public Map<String, Object> requests(Long app, Visibility visible, String status, String keyword, int page, int size) {
        return DddBoundary.execute(() -> {
            AccessRequestAggregate.validateStatusFilter(status);
            var slice = governance.requests(app, DddBoundary.toDomainVisibility(visible), status, keyword, page, size);
            return RbacUseCase.page(slice.items(), slice.total(), page, size);
        });
    }

    @Override
    public Map<String, Object> request(long id) {
        return DddBoundary.execute(() -> governance.requestView(id)
                .orElseThrow(() -> DomainException.missing("申请不存在")));
    }

    @Override
    @Transactional
    public Map<String, Object> submit(long app, Requests.AccessRequestSubmit body, String actor) {
        return DddBoundary.execute(() -> {
            long user = rbacRepo.lockUserByExternalId(body.externalId())
                    .orElseThrow(() -> DomainException.missing("用户不存在"));
            AccessRequestAggregate.validateSubmission(
                    rbacRepo.isLockedMember(user, body.departmentId()),
                    rbacRepo.scopedExists("roles", body.roleId(), body.departmentId(), app),
                    governance.pendingRequestExists(user, body.roleId()));
            long id;
            try {
                id = governance.createRequest(user, body.departmentId(), app, body.roleId(),
                        body.reason().strip(), body.durationDays(), actor);
            } catch (DuplicateKeyException e) {
                throw DomainException.conflict("该用户已有此角色的待审批申请");
            }
            rbac.audit(actor, "ACCESS_REQUESTED", body.externalId(), body.departmentId(), app, "角色 #" + body.roleId());
            return request(id);
        });
    }

    @Override
    @Transactional
    public Map<String, Object> approve(long id, Requests.RequestApprove body, String actor) {
        return DddBoundary.execute(() -> {
            var aggregate = governance.findRequest(id).orElseThrow(() -> DomainException.missing("申请不存在"));
            var plan = aggregate.planApproval(body.permanent(), body.durationDays(), body.comment(), Instant.now());
            rbacRepo.lockUser(plan.userId()).orElseThrow(() -> DomainException.missing("用户不存在"));
            if (!rbacRepo.isLockedMember(plan.userId(), plan.departmentId())) {
                throw DomainException.conflict("用户已不属于该部门，无法授权");
            }
            rbacRepo.grantRole(plan.userId(), plan.departmentId(), plan.applicationId(), plan.roleId(), plan.expiresAt(), actor);
            if (governance.decideRequest(id, "APPROVED", actor, plan.comment(), plan.expiresAt()) == 0) {
                throw DomainException.conflict("申请已被并发处理");
            }
            contexts.revokeDomain(plan.userId(), plan.departmentId(), plan.applicationId());
            cache.touchUser(plan.userId());
            events.emit(plan.applicationId(), "access.approved", Map.of(
                    "userId", plan.userId(), "externalId", plan.externalId(),
                    "departmentId", plan.departmentId(), "roleId", plan.roleId()));
            rbac.audit(actor, "ACCESS_REQUEST_APPROVED", plan.externalId(), plan.departmentId(), plan.applicationId(),
                    plan.auditDetail());
            return request(id);
        });
    }

    @Override
    @Transactional
    public Map<String, Object> reject(long id, Requests.RequestReject body, String actor) {
        return DddBoundary.execute(() -> {
            var aggregate = governance.findRequest(id).orElseThrow(() -> DomainException.missing("申请不存在"));
            aggregate.assertRejectable();
            String comment = text(body.comment());
            if (governance.decideRequest(id, "REJECTED", actor, comment, null) == 0) {
                throw DomainException.conflict("申请已被并发处理");
            }
            var data = new LinkedHashMap<String, Object>();
            data.put("userId", aggregate.userId());
            data.put("externalId", aggregate.externalId());
            data.put("departmentId", aggregate.departmentId());
            data.put("roleId", aggregate.roleId());
            data.put("comment", comment);
            events.emit(aggregate.applicationId(), "access.rejected", data);
            rbac.audit(actor, "ACCESS_REQUEST_REJECTED", aggregate.externalId(), aggregate.departmentId(),
                    aggregate.applicationId(), "角色 " + aggregate.roleCode()
                            + (body.comment() == null || body.comment().isBlank() ? "" : "，理由：" + body.comment()));
            return request(id);
        });
    }

    @Override
    @Transactional
    public void cancelOwn(long app, long id, String externalId, String actor) {
        DddBoundary.run(() -> {
            long user = rbacRepo.userIdByExternalId(externalId).orElseThrow(() -> DomainException.missing("用户不存在"));
            var aggregate = governance.findRequest(id).orElseThrow(() -> DomainException.missing("申请不存在"));
            aggregate.assertOwnedByApplicant(app, user);
            if (governance.cancelOwnRequest(id, user) == 0) {
                throw DomainException.conflict("申请已被处理，无法撤回");
            }
            rbac.audit(actor, "ACCESS_REQUEST_CANCELLED", externalId, aggregate.departmentId(), app,
                    "角色 " + aggregate.roleCode());
        });
    }

    @Override
    public List<Map<String, Object>> myRequests(long app, String externalId) {
        return DddBoundary.execute(() -> {
            long user = rbacRepo.userIdByExternalId(externalId).orElseThrow(() -> DomainException.missing("用户不存在"));
            return governance.requestsOfUser(user, app);
        });
    }

    @Override
    public Map<String, Object> myAccess(long app, String externalId, long dept) {
        return DddBoundary.execute(() -> {
            long user = rbacRepo.userIdByExternalId(externalId).orElseThrow(() -> DomainException.missing("用户不存在"));
            rbac.domain(dept, app);
            if (!rbacRepo.isMember(user, dept)) throw DomainException.forbidden("用户不属于目标部门");
            var aggregate = new DomainAuthorizationAggregate(new IsolationDomain(dept, app));
            var prep = aggregate.prepareSelfAccess(rbacRepo.assignedRolesInDomain(user, dept, app), Instant.now());
            var grants = rbacRepo.permissionGrantsTyped(prep.usableRoleIds());
            return aggregate.buildSelfAccessResult(user, prep, grants);
        });
    }

    @Override
    @Transactional
    public Map<String, Object> createReview(Requests.ReviewCreate body, String actor) {
        return DddBoundary.execute(() -> {
            if (!rbacRepo.applicationExists(body.applicationId())) throw DomainException.missing("软件不存在");
            if (body.departmentId() != null && !rbacRepo.departmentExists(body.departmentId())) {
                throw DomainException.missing("部门不存在");
            }
            Instant due = body.dueDays() == null ? null : Instant.now().truncatedTo(ChronoUnit.SECONDS).plus(body.dueDays(), ChronoUnit.DAYS);
            long id = governance.createReview(body.name().strip(), body.applicationId(), body.departmentId(), due, actor);
            int items = governance.insertReviewSnapshot(id, body.applicationId(), body.departmentId());
            rbac.audit(actor, "REVIEW_CREATED", body.name(), body.departmentId(), body.applicationId(), "快照包含 " + items + " 条授权");
            return review(id);
        });
    }

    @Override
    public Map<String, Object> review(long id) {
        return DddBoundary.execute(() -> governance.reviewView(id)
                .orElseThrow(() -> DomainException.missing("复核不存在")));
    }

    @Override
    public List<Map<String, Object>> reviews(Long app, Visibility visible, String status) {
        return DddBoundary.execute(() -> {
            AccessReviewAggregate.validateStatusFilter(status);
            return governance.reviews(app, DddBoundary.toDomainVisibility(visible), status);
        });
    }

    @Override
    public Map<String, Object> reviewItems(long reviewId, String decision, int page, int size) {
        return DddBoundary.execute(() -> {
            review(reviewId);
            AccessReviewAggregate.validateDecisionFilter(decision);
            var slice = governance.reviewItems(reviewId, decision, page, size);
            return RbacUseCase.page(slice.items(), slice.total(), page, size);
        });
    }

    @Override
    @Transactional
    public void decideReviewItem(long reviewId, long itemId, Requests.ReviewItemDecision body, String actor) {
        DddBoundary.run(() -> {
            lockOpenReview(reviewId);
            if (governance.decideReviewItem(itemId, reviewId, body.decision(), actor, text(body.comment())) == 0) {
                throw DomainException.missing("复核条目不存在");
            }
        });
    }

    @Override
    @Transactional
    public Map<String, Object> closeReview(long reviewId, String actor) {
        return DddBoundary.execute(() -> {
            lockOpenReview(reviewId);
            var review = governance.findReview(reviewId).orElseThrow(() -> DomainException.missing("复核不存在"));
            var revocations = governance.pendingRevocations(reviewId);
            rbacRepo.lockUsers(AccessReviewAggregate.orderedUsersToLock(revocations));
            var domains = new LinkedHashMap<Long, List<Long>>();
            var touched = new LinkedHashSet<Long>();
            int revoked = 0, skipped = 0;
            for (var item : revocations) {
                boolean applied = item.canAttemptRevoke()
                        && governance.revokeMatchingGrant(item.userId(), item.roleId(), item.grantId()) > 0;
                governance.markReviewItemApplied(item.itemId(), !applied);
                if (!applied) {
                    skipped++;
                    continue;
                }
                revoked++;
                touched.add(item.userId());
                domains.computeIfAbsent(item.departmentId(), k -> new ArrayList<>()).add(item.userId());
            }
            for (var entry : domains.entrySet()) {
                contexts.revokeDomainForUsers(entry.getValue(), entry.getKey(), review.applicationId());
            }
            for (long user : touched) cache.touchUser(user);
            String summary = AccessReviewAggregate.closeSummary(revoked, skipped);
            if (governance.closeReview(reviewId, actor, summary) == 0) {
                throw DomainException.conflict("复核已被并发关闭");
            }
            if (revoked > 0) {
                events.emit(review.applicationId(), "review.closed", Map.of("reviewId", reviewId, "revoked", revoked));
            }
            rbac.audit(actor, "REVIEW_CLOSED", review.name(), review.departmentId(), review.applicationId(), summary);
            return review(reviewId);
        });
    }

    @Override
    @Transactional
    public int expireAssignments(int limit) {
        var lapsed = new LinkedHashMap<String, List<Map<String, Object>>>();
        for (var row : rbacRepo.lapsedAssignments(limit)) {
            if (rbacRepo.deleteLapsedAssignment(number(row.get("userId")), number(row.get("roleId"))) == 0) continue;
            lapsed.computeIfAbsent(row.get("userId") + ":" + row.get("departmentId") + ":" + row.get("applicationId"),
                    k -> new ArrayList<>()).add(row);
        }
        int expired = 0;
        for (var rows : lapsed.values()) {
            var first = rows.get(0);
            long user = number(first.get("userId"));
            long dept = number(first.get("departmentId"));
            long app = number(first.get("applicationId"));
            String external = (String) first.get("externalId");
            cache.touchUser(user);
            events.emit(app, "user.roles.expired", Map.of("userId", user, "externalId", external, "departmentId", dept,
                    "roleIds", rows.stream().map(r -> number(r.get("roleId"))).toList()));
            rbac.audit("system", "USER_ROLES_EXPIRED", external, dept, app,
                    "到期角色 " + rows.stream().map(r -> (String) r.get("roleCode")).collect(Collectors.joining("、")));
            expired += rows.size();
        }
        return expired;
    }

    @Override
    @Transactional
    public Map<String, Object> importUsers(Requests.UserImport body, String actor) {
        var codes = new LinkedHashSet<String>();
        for (var row : body.users()) if (row != null && row.departmentCodes() != null) codes.addAll(row.departmentCodes());
        codes.removeIf(Objects::isNull);
        var departmentByCode = new HashMap<String, Long>();
        for (var row : rbacRepo.departmentIdsByCodes(codes)) departmentByCode.put((String) row.get("code"), number(row.get("id")));
        int created = 0, updated = 0;
        var failures = new ArrayList<Map<String, Object>>();
        int line = 0;
        for (var row : body.users()) {
            line++;
            try {
                validateImportRow(row);
                var wanted = new LinkedHashSet<Long>();
                for (String code : row.departmentCodes()) {
                    Long dept = departmentByCode.get(code);
                    if (dept == null) throw DomainException.missing("部门编码不存在: " + code);
                    wanted.add(dept);
                }
                String email = row.email() == null ? "" : row.email().strip();
                var existing = rbacRepo.lockUserByExternalId(row.externalId());
                long userId;
                if (existing.isPresent()) {
                    userId = existing.get();
                    rbacRepo.updateUserProfile(userId, row.name().strip(), email);
                    updated++;
                } else {
                    userId = rbacRepo.createUser(row.name().strip(), row.externalId(), email);
                    created++;
                }
                var current = new HashSet<>(rbacRepo.lockedUserDepartments(userId));
                for (long dept : wanted) if (!current.contains(dept)) rbacRepo.addMembership(userId, dept);
            } catch (DomainException | ApiException | DataIntegrityViolationException e) {
                var failure = new LinkedHashMap<String, Object>();
                failure.put("line", line);
                failure.put("externalId", row == null ? null : row.externalId());
                failure.put("error", (e instanceof DomainException || e instanceof ApiException)
                        ? e.getMessage() : "外部标识已存在或关联数据冲突");
                failures.add(failure);
            }
        }
        rbac.audit(actor, "USER_IMPORTED", "users", null, null,
                "新建 " + created + "，更新 " + updated + "，失败 " + failures.size());
        var result = new LinkedHashMap<String, Object>();
        result.put("created", created);
        result.put("updated", updated);
        result.put("failed", failures);
        return result;
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> exportManifest(long app, Long departmentFilter, Collection<Long> visibleDepartments) {
        return DddBoundary.execute(() -> {
            var application = rbacRepo.applicationRow(app).orElseThrow(() -> DomainException.missing("软件不存在"));
            var departmentsById = new HashMap<Long, Map<String, Object>>();
            for (var department : rbac.departments(null)) departmentsById.put(number(department.get("id")), department);
            List<Long> departmentIds = departmentFilter != null ? List.of(departmentFilter)
                    : rbacRepo.manifestDepartmentIds(app).stream()
                            .filter(id -> visibleDepartments == null || visibleDepartments.contains(id)).toList();
            var sections = new ArrayList<Map<String, Object>>();
            for (long dept : departmentIds) {
                var department = departmentsById.get(dept);
                if (department == null) continue;
                var permissions = new ArrayList<Map<String, Object>>();
                var codesById = new HashMap<Long, String>();
                for (var p : rbacRepo.permissions(dept, app)) {
                    codesById.put(number(p.get("id")), (String) p.get("code"));
                    var item = new LinkedHashMap<String, Object>();
                    item.put("code", p.get("code"));
                    item.put("name", p.get("name"));
                    item.put("resource", p.get("resource"));
                    item.put("action", p.get("action"));
                    permissions.add(item);
                }
                var grantsByRole = new HashMap<Long, List<String>>();
                for (var pair : rbacRepo.domainRolePermissionPairs(dept, app)) {
                    String code = codesById.get(number(pair.get("permission_id")));
                    if (code != null) grantsByRole.computeIfAbsent(number(pair.get("role_id")), k -> new ArrayList<>()).add(code);
                }
                var roles = new ArrayList<Map<String, Object>>();
                for (var r : rbacRepo.roles(dept, app)) {
                    var item = new LinkedHashMap<String, Object>();
                    item.put("code", r.get("code"));
                    item.put("name", r.get("name"));
                    item.put("description", r.get("description"));
                    item.put("enabled", r.get("enabled"));
                    item.put("permissions", grantsByRole.getOrDefault(number(r.get("id")), List.of()));
                    roles.add(item);
                }
                var section = new LinkedHashMap<String, Object>();
                section.put("code", department.get("code"));
                section.put("name", department.get("name"));
                section.put("permissions", permissions);
                section.put("roles", roles);
                sections.add(section);
            }
            var manifest = new LinkedHashMap<String, Object>();
            manifest.put("version", 1);
            manifest.put("application", Map.of("code", application.get("code"), "name", application.get("name")));
            manifest.put("exportedAt", Instant.now().toString());
            manifest.put("departments", sections);
            return manifest;
        });
    }

    @Override
    @Transactional
    public Map<String, Object> importManifest(long app, Requests.Manifest manifest, String actor, Collection<Long> scope) {
        return DddBoundary.execute(() -> {
            if (!rbacRepo.applicationExists(app)) throw DomainException.missing("软件不存在");
            var codes = manifest.departments().stream().map(Requests.ManifestDepartment::code).toList();
            var departmentByCode = new HashMap<String, Long>();
            for (var row : rbacRepo.departmentIdsByCodes(codes)) departmentByCode.put((String) row.get("code"), number(row.get("id")));
            for (String code : codes) {
                if (!departmentByCode.containsKey(code)) throw DomainException.missing("部门编码不存在: " + code);
            }
            if (scope != null && !scope.containsAll(departmentByCode.values())) {
                throw DomainException.forbidden("清单中包含你管理范围以外的部门");
            }
            int permissionsCreated = 0, permissionsUpdated = 0, rolesCreated = 0, rolesUpdated = 0;
            for (var section : manifest.departments()) {
                long dept = departmentByCode.get(section.code());
                var wasEnabled = new HashMap<Long, Boolean>();
                for (var role : rbacRepo.roles(dept, app)) wasEnabled.put(number(role.get("id")), Boolean.TRUE.equals(role.get("enabled")));
                var permissionIds = new HashMap<String, Long>();
                for (var p : section.permissions()) {
                    var existing = rbacRepo.scopedIdByCode("permissions", dept, app, p.code());
                    if (existing.isPresent()) {
                        rbacRepo.updatePermission(existing.get(), p.name(), p.code(), p.resource(), p.action());
                        permissionIds.put(p.code(), existing.get());
                        permissionsUpdated++;
                    } else {
                        permissionIds.put(p.code(), rbacRepo.createPermission(dept, app, p.name(), p.code(), p.resource(), p.action()));
                        permissionsCreated++;
                    }
                }
                for (var r : section.roles()) {
                    var grants = new LinkedHashSet<Long>();
                    for (String code : r.permissions()) {
                        Long permissionId = permissionIds.get(code);
                        if (permissionId == null) {
                            permissionId = rbacRepo.scopedIdByCode("permissions", dept, app, code)
                                    .orElseThrow(() -> DomainException.bad("角色 " + r.code() + " 引用了不存在的权限编码 " + code));
                        }
                        grants.add(permissionId);
                    }
                    boolean enabled = r.enabled() == null || r.enabled();
                    Long roleId = rbacRepo.scopedIdByCode("roles", dept, app, r.code()).orElse(null);
                    if (roleId == null) {
                        rbacRepo.replaceRolePermissions(
                                rbacRepo.createRole(dept, app, r.name(), r.code(), text(r.description()), enabled),
                                dept, app, grants);
                        rolesCreated++;
                    } else {
                        var before = new HashSet<>(rbacRepo.rolePermissionIds(roleId));
                        rbacRepo.updateRole(roleId, r.name(), r.code(), text(r.description()));
                        rbacRepo.updateRoleStatus(roleId, enabled);
                        rbacRepo.replaceRolePermissions(roleId, dept, app, grants);
                        if (enabled != Boolean.TRUE.equals(wasEnabled.get(roleId))) {
                            events.emit(app, enabled ? "role.enabled" : "role.disabled", Map.of("roleId", roleId, "departmentId", dept));
                        }
                        if (!before.equals(grants)) {
                            events.emit(app, "role.permissions.changed", Map.of("roleId", roleId, "departmentId", dept));
                        }
                        rolesUpdated++;
                    }
                }
                cache.touchDomain(dept, app);
            }
            rbac.audit(actor, "MANIFEST_IMPORTED", "application:" + app, null, app,
                    "新建权限 " + permissionsCreated + "、更新权限 " + permissionsUpdated
                            + "、新建角色 " + rolesCreated + "、更新角色 " + rolesUpdated);
            var result = new LinkedHashMap<String, Object>();
            result.put("permissionsCreated", permissionsCreated);
            result.put("permissionsUpdated", permissionsUpdated);
            result.put("rolesCreated", rolesCreated);
            result.put("rolesUpdated", rolesUpdated);
            return result;
        });
    }

    @Override
    public Map<String, Object> permissionHolders(long app, String code, Long department, Collection<Long> visibleDepartments) {
        return DddBoundary.execute(() -> {
            if (!rbacRepo.applicationExists(app)) throw DomainException.missing("软件不存在");
            var grouped = new LinkedHashMap<String, Map<String, Object>>();
            for (var row : rbacRepo.permissionHolders(app, code, department, visibleDepartments, HOLDER_LIMIT)) {
                var holder = grouped.computeIfAbsent(row.get("userId") + ":" + row.get("departmentId"), k -> {
                    var h = new LinkedHashMap<String, Object>();
                    h.put("userId", number(row.get("userId")));
                    h.put("userName", row.get("userName"));
                    h.put("externalId", row.get("externalId"));
                    h.put("departmentId", number(row.get("departmentId")));
                    h.put("departmentName", row.get("departmentName"));
                    h.put("roles", new ArrayList<Map<String, Object>>());
                    return h;
                });
                var role = new LinkedHashMap<String, Object>();
                role.put("id", number(row.get("roleId")));
                role.put("name", row.get("roleName"));
                role.put("code", row.get("roleCode"));
                role.put("expiresAt", row.get("expiresAt"));
                rows(holder.get("roles")).add(role);
            }
            var result = new LinkedHashMap<String, Object>();
            result.put("code", code);
            result.put("applicationId", app);
            long total = rbacRepo.permissionHolderCount(app, code, department, visibleDepartments);
            result.put("holders", new ArrayList<>(grouped.values()));
            result.put("total", total);
            result.put("truncated", total > grouped.size());
            return result;
        });
    }

    @Override
    public List<Map<String, Object>> expiringAssignments(int days, Visibility visible, Long app) {
        return rbacRepo.expiringAssignments(Instant.now().plus(days, ChronoUnit.DAYS),
                DddBoundary.toDomainVisibility(visible), app);
    }

    private void lockOpenReview(long reviewId) {
        String status = governance.lockReviewStatus(reviewId).orElseThrow(() -> DomainException.missing("复核不存在"));
        AccessReviewAggregate.assertOpenStatus(status);
    }

    private void validateImportRow(Requests.UserImportRow row) {
        if (row == null) throw DomainException.bad("该行为空");
        var fields = new TreeSet<String>();
        for (var violation : validator.validate(row)) {
            var node = violation.getPropertyPath().iterator();
            fields.add(node.hasNext() ? node.next().getName() : "row");
        }
        if (!fields.isEmpty()) throw DomainException.bad("字段 " + String.join("、", fields) + " 缺失或格式不正确");
    }

    private static long number(Object value) { return ((Number) value).longValue(); }
    private static String text(String value) { return Objects.requireNonNullElse(value, "").strip(); }
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> rows(Object value) { return (List<Map<String, Object>>) value; }
}
