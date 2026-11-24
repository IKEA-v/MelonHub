package com.melonhub.rbac.service.ddd.application;

import cn.edu.xmu.clonefactory.util.CloneFactory;
import com.melonhub.rbac.dto.ContextContracts.CheckResult;
import com.melonhub.rbac.dto.ContextContracts.ContextResult;
import com.melonhub.rbac.dto.ContextContracts.IssueCommand;
import com.melonhub.rbac.dto.ContextContracts.Role;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.service.ddd.domain.model.PermissionContextAggregate;
import com.melonhub.rbac.service.ddd.domain.model.PermissionContextAggregate.ContextSubject;
import com.melonhub.rbac.service.ddd.domain.model.PermissionContextAggregate.EffectiveRole;
import com.melonhub.rbac.service.ddd.domain.model.PermissionContextAggregate.EffectiveSnapshot;
import com.melonhub.rbac.service.ddd.domain.repository.PermissionContextRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.CacheGateway;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.CacheLookupStatus;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.CryptoGateway;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.JsonCodec;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.TransactionRunner;
import com.melonhub.rbac.service.ddd.domain.value.DomainException;
import com.melonhub.rbac.service.port.ContextUseCase;
import com.melonhub.rbac.service.port.RbacUseCase;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * DDD 应用服务：业务系统权限上下文签发、生效查询、批量鉴权与撤销。
 * 部门切换保护、激活角色子集规则、最早到期刷新时间与鉴权评估全部委托给 {@link PermissionContextAggregate}。
 */
@Service
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class DddContextService implements ContextUseCase {
    private record Meta(String u, String d, String a, long v, long exp) {
        long user() { return Long.parseLong(u); }
        long department() { return Long.parseLong(d); }
        long application() { return Long.parseLong(a); }
        boolean usableFor(long app) { return application() == app && exp > Instant.now().getEpochSecond(); }
    }

    private record Payload(boolean valid, List<Role> roles, List<String> permissions, Long refreshAt) {
        static final Payload INVALID = new Payload(false, List.of(), List.of(), null);
        boolean lapsed() { return refreshAt != null && refreshAt <= Instant.now().getEpochSecond(); }
    }

    private record Access(Meta meta, Payload payload) {}

    private final PermissionContextRepositoryPort repository;
    private final RbacUseCase rbac;
    private final CacheGateway cache;
    private final CryptoGateway crypto;
    private final JsonCodec json;
    private final TransactionRunner transactions;

    public DddContextService(PermissionContextRepositoryPort repository, RbacUseCase rbac, CacheGateway cache,
                             CryptoGateway crypto, JsonCodec json, TransactionRunner transactions) {
        this.repository = repository;
        this.rbac = rbac;
        this.cache = cache;
        this.crypto = crypto;
        this.json = json;
        this.transactions = transactions;
    }

    @Override
    @Transactional
    public Map<String, Object> issue(long app, Requests.Context input, String actor) {
        return view(issueContext(app, CloneFactory.copy(new IssueCommand(), input), actor));
    }

    @Override
    @Transactional
    public ContextResult issueContext(long app, IssueCommand input, String actor) {
        return DddBoundary.execute(() -> {
            long departmentId = input.getDepartmentId();
            String externalId = input.getExternalId();
            rbac.domain(departmentId, app);
            var user = repository.lockUserByExternalId(externalId)
                    .orElseThrow(() -> DomainException.missing("用户不存在"));
            boolean appEnabled = repository.isApplicationEnabled(app);
            boolean member = repository.isMember(user.userId(), departmentId);
            var assigned = repository.assignedRoleIds(user.userId(), departmentId, app);
            var subject = new ContextSubject(user.userId(), user.enabled(), user.activeDepartmentId(),
                    user.contextVersion(), appEnabled, member, assigned);
            var plan = PermissionContextAggregate.planIssuance(
                    app, departmentId, input.getActiveRoleIds(), input.getSwitchDepartment(),
                    subject, Instant.now(), CONTEXT_SECONDS);

            if (plan.switchedDepartment()) {
                repository.switchDepartment(plan.userId(), plan.departmentId(), plan.contextVersion());
                cache.touchUser(plan.userId());
            }
            repository.clearStaleContexts(plan.userId(), plan.contextVersion());
            String token = crypto.generateToken();
            String hash = crypto.hashToken(token);
            repository.createContext(hash, plan.userId(), plan.departmentId(), plan.applicationId(),
                    plan.contextVersion(), plan.expiresAt());
            repository.activateRoles(hash, plan.activeRoleIds());
            rbac.audit(actor, "CONTEXT_ISSUED", externalId, plan.departmentId(), plan.applicationId(),
                    "激活角色 " + plan.activeRoleIds().size() + " 个" + (plan.switchedDepartment() ? "，切换当前部门" : ""));
            var meta = new Meta(String.valueOf(plan.userId()), String.valueOf(plan.departmentId()),
                    String.valueOf(plan.applicationId()), plan.contextVersion(), plan.expiresAt().getEpochSecond());
            var access = new Access(meta, compute(hash, meta));
            cache.putContextAfterCommit(hash, json.write(meta), CONTEXT_SECONDS);
            return contextResult(access, token);
        });
    }

    @Override
    public Map<String, Object> effective(long app, String token) {
        return view(effectiveContext(app, token));
    }

    @Override
    public ContextResult effectiveContext(long app, String token) {
        return contextResult(resolve(app, token), null);
    }

    @Override
    public Map<String, Object> check(long app, String token, List<String> requested) {
        var check = checkPermissions(app, token, requested);
        var result = new LinkedHashMap<String, Object>();
        result.put("allowed", check.allowed());
        result.put("decisions", check.decisions());
        result.put("contextVersion", check.contextVersion());
        return result;
    }

    @Override
    public CheckResult checkPermissions(long app, String token, List<String> requested) {
        var access = resolve(app, token);
        var snapshot = new EffectiveSnapshot(
                access.meta().user(), access.meta().department(), access.meta().application(),
                access.meta().v(), Instant.ofEpochSecond(access.meta().exp()),
                List.of(), access.payload().permissions(),
                access.payload().refreshAt() == null ? null : Instant.ofEpochSecond(access.payload().refreshAt()));
        var outcome = snapshot.evaluate(requested);
        return new CheckResult(outcome.allowed(), outcome.decisions(), outcome.contextVersion());
    }

    @Override
    @Transactional
    public void revoke(long app, String token, String actor) {
        var access = resolve(app, token);
        String hash = crypto.hashToken(token);
        repository.revokeByHash(hash, app);
        cache.touchUser(access.meta().user());
        cache.forgetContextAfterCommit(hash);
        rbac.audit(actor, "CONTEXT_REVOKED", "user:" + access.meta().u(), access.meta().department(), app, "");
    }

    private Access resolve(long app, String token) {
        String hash = crypto.hashTokenOrNull(token);
        if (hash == null) throw ApiException.contextInvalid();
        var lookup = cache.lookupContext(hash);
        Meta cachedMeta = lookup.meta() == null ? null : json.readOrNull(lookup.meta(), Meta.class);
        if (lookup.status() == CacheLookupStatus.HIT && cachedMeta != null) {
            Payload payload = json.readOrNull(lookup.payload(), Payload.class);
            if (payload != null && !payload.lapsed()) {
                if (!cachedMeta.usableFor(app) || !payload.valid()) throw ApiException.contextInvalid();
                return new Access(cachedMeta, payload);
            }
        }
        if (cachedMeta != null && !cachedMeta.usableFor(app)) throw ApiException.contextInvalid();
        Access loaded = transactions.inReadOnlyTransaction(() -> load(hash));
        String storeKey = lookup.status() == CacheLookupStatus.MISS ? lookup.storeKey() : null;
        if (loaded == null) {
            cache.storePayload(storeKey, json.write(Payload.INVALID), CacheGateway.DEFAULT_TTL_SECONDS);
            throw ApiException.contextInvalid();
        }
        long now = Instant.now().getEpochSecond();
        long remaining = loaded.meta().exp() - now;
        if (lookup.status() == CacheLookupStatus.NONE) {
            cache.putContext(hash, json.write(loaded.meta()), remaining);
        }
        long ttl = Math.min(CacheGateway.DEFAULT_TTL_SECONDS, remaining);
        if (loaded.payload().refreshAt() != null) {
            ttl = Math.min(ttl, loaded.payload().refreshAt() - now);
        }
        cache.storePayload(storeKey, json.write(loaded.payload()), ttl);
        if (!loaded.meta().usableFor(app) || !loaded.payload().valid()) throw ApiException.contextInvalid();
        return loaded;
    }

    private Access load(String hash) {
        var found = repository.contextState(hash);
        if (found.isEmpty()) return null;
        var row = found.get();
        var meta = new Meta(String.valueOf(row.userId()), String.valueOf(row.departmentId()),
                String.valueOf(row.applicationId()), row.contextVersion(), row.expiresAt().getEpochSecond());
        return new Access(meta, row.valid() ? compute(hash, meta) : Payload.INVALID);
    }

    private Payload compute(String hash, Meta meta) {
        var effectiveRoles = repository.effectiveRoles(meta.user(), hash, meta.department(), meta.application());
        var roles = effectiveRoles.stream().map(r -> new Role(r.id(), r.name(), r.code())).toList();
        var roleExpiries = effectiveRoles.stream().map(EffectiveRole::expiresAt).filter(java.util.Objects::nonNull).toList();
        Instant earliest = roleExpiries.isEmpty() ? null : PermissionContextAggregate.earliestRefreshAt(null, roleExpiries);
        Long refreshAt = earliest == null ? null : earliest.getEpochSecond();
        var permissions = repository.effectivePermissions(meta.user(), hash, meta.department(), meta.application());
        return new Payload(true, roles, permissions, refreshAt);
    }

    private static ContextResult contextResult(Access access, String token) {
        var meta = access.meta();
        return new ContextResult(token, meta.user(), meta.department(), meta.application(), meta.v(),
                Instant.ofEpochSecond(meta.exp()), access.payload().roles(), access.payload().permissions());
    }

    private static Map<String, Object> view(ContextResult context) {
        var result = new LinkedHashMap<String, Object>();
        if (context.contextToken() != null) result.put("contextToken", context.contextToken());
        result.put("userId", context.userId());
        result.put("departmentId", context.departmentId());
        result.put("applicationId", context.applicationId());
        result.put("contextVersion", context.contextVersion());
        result.put("expiresAt", context.expiresAt());
        result.put("roles", context.roles());
        result.put("permissions", context.permissions());
        return result;
    }
}
