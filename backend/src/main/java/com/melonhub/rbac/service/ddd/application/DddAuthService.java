package com.melonhub.rbac.service.ddd.application;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.security.AdminFunction;
import com.melonhub.rbac.security.AdminPrincipal;
import com.melonhub.rbac.security.ApplicationCaller;
import com.melonhub.rbac.service.ddd.domain.model.AdminCredentialAccount;
import com.melonhub.rbac.service.ddd.domain.model.AdminHierarchy;
import com.melonhub.rbac.service.ddd.domain.repository.AdminAccountRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.repository.AdminRoleRepositoryPort;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.CacheGateway;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.CacheLookupStatus;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.CryptoGateway;
import com.melonhub.rbac.service.ddd.domain.repository.PlatformGatewayPorts.JsonCodec;
import com.melonhub.rbac.service.ddd.domain.value.AdminScope;
import com.melonhub.rbac.service.ddd.domain.value.DomainException;
import com.melonhub.rbac.service.ddd.domain.value.PasswordPolicy;
import com.melonhub.rbac.service.port.AuthUseCase;
import com.melonhub.rbac.service.port.RbacUseCase;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * DDD 应用服务：管理员登录认证、会话与 MFA 管理、API Key 校验以及管理员层级树维护。
 * 所有登录状态机由 {@link AdminCredentialAccount} 决策，层级树不变量由 {@link AdminHierarchy} 聚合根守护。
 */
@Service
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class DddAuthService implements AuthUseCase, ApplicationRunner {
    private record KeyMeta(String a, long k) {}
    private record KeyState(boolean valid, Long exp) {}

    private static final Logger log = LoggerFactory.getLogger(DddAuthService.class);

    private final AdminAccountRepositoryPort accounts;
    private final AdminRoleRepositoryPort roles;
    private final RbacUseCase rbac;
    private final CacheGateway cache;
    private final CryptoGateway crypto;
    private final JsonCodec json;
    private final String bootstrapUser;
    private final String bootstrapPassword;
    private final boolean bootstrapReset;
    private final int maxFailures;
    private final int lockMinutes;
    private final int sessionSeconds;
    private final int idleMinutes;
    private final Set<Long> usedKeys = ConcurrentHashMap.newKeySet();

    public DddAuthService(AdminAccountRepositoryPort accounts, AdminRoleRepositoryPort roles, RbacUseCase rbac,
                          CacheGateway cache, CryptoGateway crypto, JsonCodec json,
                          @Value("${melonhub.admin-username}") String bootstrapUser,
                          @Value("${melonhub.admin-password}") String bootstrapPassword,
                          @Value("${melonhub.admin-password-reset:false}") boolean bootstrapReset,
                          @Value("${melonhub.admin-security.max-failures:5}") int maxFailures,
                          @Value("${melonhub.admin-security.lock-minutes:15}") int lockMinutes,
                          @Value("${melonhub.admin-security.session-hours:8}") int sessionHours,
                          @Value("${melonhub.admin-security.idle-minutes:30}") int idleMinutes) {
        this.accounts = accounts;
        this.roles = roles;
        this.rbac = rbac;
        this.cache = cache;
        this.crypto = crypto;
        this.json = json;
        this.bootstrapUser = bootstrapUser;
        this.bootstrapPassword = bootstrapPassword;
        this.bootstrapReset = bootstrapReset;
        this.maxFailures = maxFailures;
        this.lockMinutes = lockMinutes;
        this.sessionSeconds = sessionHours * 3600;
        this.idleMinutes = idleMinutes;
    }

    @Override
    public void run(ApplicationArguments args) {
        PasswordPolicy.validateBootstrapAdmin(bootstrapUser, bootstrapPassword);
        if (!accounts.accountExists(bootstrapUser)) {
            accounts.createAccount(bootstrapUser, "平台管理员", AdminPrincipal.SUPER_ADMIN,
                    crypto.encodeAdminPassword(bootstrapPassword), true, null, AdminPrincipal.MANAGER, true, true);
            log.info("Bootstrap super administrator account created");
        } else if (bootstrapReset) {
            accounts.resetBootstrap(bootstrapUser, crypto.encodeAdminPassword(bootstrapPassword), AdminPrincipal.SUPER_ADMIN);
            accounts.findAccountByUsername(bootstrapUser).ifPresent(a -> accounts.endAllSessions(a.id()));
            log.warn("Bootstrap administrator restored from ADMIN_PASSWORD; set ADMIN_PASSWORD_RESET=false again");
        }
        accounts.purgeSessions(idleMinutes, 100_000);
    }

    @Override
    public Map<String, Object> login(Requests.Login input) {
        return DddBoundary.execute(() -> {
            String username = input.username();
            var found = accounts.findAccountByUsername(username);
            if (found.isEmpty()) {
                crypto.consumeDummyAdminCheck();
                rbac.audit(username, "LOGIN_FAILED", username, null, null, "账号不存在");
                throw badCredentials();
            }
            var account = found.get();
            if (account.locked()) {
                rbac.audit(username, "LOGIN_BLOCKED", username, null, null, "账号处于锁定期");
                throw locked();
            }
            boolean passwordMatches = !PasswordPolicy.exceedsBcryptLimit(input.password())
                    && crypto.matchesAdminPassword(input.password(), account.passwordHash());
            if (!passwordMatches && PasswordPolicy.exceedsBcryptLimit(input.password())) {
                crypto.consumeDummyAdminCheck();
            }
            Long verifiedStep = null;
            if (passwordMatches && account.enabled() && account.mfaEnabled()
                    && input.mfaCode() != null && !input.mfaCode().isBlank()) {
                verifiedStep = crypto.verifyTotp(account.mfaSecret(), input.mfaCode().strip());
            }
            var outcome = account.evaluateLogin(passwordMatches, input.mfaCode(), verifiedStep);
            switch (outcome) {
                case LOCKED -> {
                    rbac.audit(username, "LOGIN_BLOCKED", username, null, null, "账号处于锁定期");
                    throw locked();
                }
                case PASSWORD_MISMATCH -> {
                    boolean nowLocked = accounts.recordFailure(account.id(), maxFailures, lockMinutes);
                    rbac.audit(username, nowLocked ? "ACCOUNT_LOCKED" : "LOGIN_FAILED", username, null, null,
                            nowLocked ? "连续 " + maxFailures + " 次密码错误，锁定 " + lockMinutes + " 分钟" : "密码错误");
                    throw nowLocked ? locked() : badCredentials();
                }
                case DISABLED -> {
                    rbac.audit(username, "LOGIN_FAILED", username, null, null, "账号已停用");
                    throw DomainException.forbidden("ACCOUNT_DISABLED", "账号已停用，请联系超级管理员");
                }
                case MFA_CODE_MISSING -> throw DomainException.unauthorized("MFA_REQUIRED", "该账号已启用两步验证，请输入认证器动态口令");
                case MFA_INVALID -> {
                    boolean nowLocked = accounts.recordFailure(account.id(), maxFailures, lockMinutes);
                    rbac.audit(username, nowLocked ? "ACCOUNT_LOCKED" : "LOGIN_FAILED", username, null, null,
                            nowLocked ? "连续失败锁定" : "动态口令不正确或已使用");
                    throw DomainException.unauthorized("MFA_INVALID", "动态口令不正确或已使用");
                }
                case READY_CONSUME_MFA -> {
                    if (accounts.consumeMfaStep(account.id(), account.mfaSecret(), verifiedStep) == 0) {
                        boolean nowLocked = accounts.recordFailure(account.id(), maxFailures, lockMinutes);
                        rbac.audit(username, nowLocked ? "ACCOUNT_LOCKED" : "LOGIN_FAILED", username, null, null,
                                nowLocked ? "连续失败锁定" : "动态口令不正确或已使用");
                        throw DomainException.unauthorized("MFA_INVALID", "动态口令不正确或已使用");
                    }
                }
                case READY_NO_MFA -> {}
            }
            String token = crypto.generateToken();
            Instant expiresAt = Instant.now().truncatedTo(ChronoUnit.SECONDS).plusSeconds(sessionSeconds);
            if (accounts.createSession(crypto.hashToken(token), account, expiresAt, crypto.currentClientAddress()) == 0) {
                rbac.audit(username, "LOGIN_FAILED", username, null, null, "登录过程中账号凭据已变更");
                throw DomainException.unauthorized("BAD_CREDENTIALS", "账号凭据已变更，请重新登录");
            }
            accounts.recordSuccess(account.id());
            rbac.audit(username, "LOGIN", username, null, null, "");
            var result = new LinkedHashMap<String, Object>();
            result.put("token", token);
            result.put("expiresIn", sessionSeconds);
            result.put("idleTimeout", idleMinutes * 60);
            result.putAll(AuthUseCase.view(principal(account.id(), account.username(), account.displayName(), account.role(),
                    account.kind(), account.root(), account.scope().allDepartments(), account.scope().allApplications())));
            result.put("mfaEnabled", account.mfaEnabled());
            return result;
        });
    }

    @Override
    public AdminPrincipal admin(String authorization) {
        String hash = sessionHash(authorization);
        var session = accounts.findActiveSession(hash, idleMinutes).orElseThrow(ApiException::unauthorized);
        if (session.stale()) accounts.touchSession(hash);
        return principal(session.id(), session.username(), session.displayName(), session.role(),
                session.kind(), session.root(), session.allDepartments(), session.allApplications());
    }

    @Override
    public String sessionHash(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) throw ApiException.unauthorized();
        String hash = crypto.hashTokenOrNull(authorization.substring(7));
        if (hash == null) throw ApiException.unauthorized();
        return hash;
    }

    @Override
    public void logout(AdminPrincipal principal, String authorization) {
        accounts.deleteSession(sessionHash(authorization));
        rbac.audit(principal.actor(), "LOGOUT", principal.username(), null, null, "");
    }

    @Override
    @Transactional
    public void changePassword(AdminPrincipal principal, String authorization, Requests.PasswordChange input) {
        DddBoundary.run(() -> {
            var account = accounts.findAccountById(principal.id()).orElseThrow(DomainException::unauthorized);
            boolean currentMatches = !PasswordPolicy.exceedsBcryptLimit(input.currentPassword())
                    && crypto.matchesAdminPassword(input.currentPassword(), account.passwordHash());
            if (!currentMatches && PasswordPolicy.exceedsBcryptLimit(input.currentPassword())) {
                crypto.consumeDummyAdminCheck();
            }
            account.validatePasswordChange(currentMatches, input.currentPassword(), input.newPassword());
            if (accounts.replacePassword(principal.id(), account.passwordHash(), crypto.encodeAdminPassword(input.newPassword())) == 0) {
                throw DomainException.bad("BAD_CREDENTIALS", "密码已被更改，请重新登录后再试");
            }
            accounts.keepOnlySession(principal.id(), sessionHash(authorization));
            rbac.audit(principal.actor(), "PASSWORD_CHANGED", principal.username(), null, null, "其他会话已下线");
        });
    }

    @Override
    public Map<String, Object> setupMfa(AdminPrincipal principal) {
        return DddBoundary.execute(() -> {
            var account = accounts.findAccountById(principal.id()).orElseThrow(DomainException::unauthorized);
            account.assertCanSetupMfa();
            String secret = crypto.generateTotpSecret();
            accounts.setMfaPendingSecret(principal.id(), secret);
            var result = new LinkedHashMap<String, Object>();
            result.put("secret", secret);
            result.put("uri", account.totpUri(secret));
            return result;
        });
    }

    @Override
    @Transactional
    public void confirmMfa(AdminPrincipal principal, String code) {
        DddBoundary.run(() -> {
            var account = accounts.findAccountById(principal.id()).orElseThrow(DomainException::unauthorized);
            String pending = accounts.findMfaPendingSecret(principal.id());
            Long step = pending == null ? null : crypto.verifyTotp(pending, code);
            account.assertCanConfirmMfa(pending, step);
            if (accounts.confirmMfa(principal.id(), pending, step) == 0) {
                throw DomainException.conflict("绑定密钥已更换，请使用最新的二维码重新绑定");
            }
            accounts.endAllSessions(principal.id());
            rbac.audit(principal.actor(), "MFA_ENABLED", principal.username(), null, null, "");
        });
    }

    @Override
    @Transactional
    public void disableMfa(AdminPrincipal principal, Requests.MfaDisable input) {
        DddBoundary.run(() -> {
            var account = accounts.findAccountById(principal.id()).orElseThrow(DomainException::unauthorized);
            boolean passwordMatches = !PasswordPolicy.exceedsBcryptLimit(input.password())
                    && crypto.matchesAdminPassword(input.password(), account.passwordHash());
            if (!passwordMatches && PasswordPolicy.exceedsBcryptLimit(input.password())) {
                crypto.consumeDummyAdminCheck();
            }
            Long step = account.mfaEnabled() ? crypto.verifyTotp(account.mfaSecret(), input.code()) : null;
            account.assertCanDisableMfa(passwordMatches, step);
            if (accounts.disableMfaWithStep(principal.id(), account.mfaSecret(), step) == 0) {
                throw DomainException.bad("MFA_INVALID", "动态口令不正确或已使用");
            }
            accounts.endAllSessions(principal.id());
            rbac.audit(principal.actor(), "MFA_DISABLED", principal.username(), null, null, "");
        });
    }

    @Override
    @Transactional
    public void resetMfa(long id, AdminPrincipal actor) {
        DddBoundary.run(() -> {
            accounts.lockAllAccounts();
            String username = hierarchy().requireManaged(actor.id(), id).username();
            if (accounts.disableMfa(id) == 0) throw DomainException.missing("管理员账号不存在");
            accounts.endAllSessions(id);
            rbac.audit(actor.actor(), "MFA_RESET", username, null, null, "两步验证已重置");
        });
    }

    @Override
    public Map<String, Object> me(AdminPrincipal principal) {
        var view = new LinkedHashMap<>(AuthUseCase.view(principal));
        view.put("mfaEnabled", accounts.findAccountById(principal.id()).map(AdminCredentialAccount::mfaEnabled).orElse(false));
        return view;
    }

    @Override
    public ApplicationCaller application(String key) {
        String hash = crypto.hashTokenOrNull(key);
        if (hash == null) throw ApiException.unauthorized();
        var lookup = cache.lookupApiKey(hash);
        if (lookup.status() == CacheLookupStatus.HIT) {
            KeyMeta meta = json.readOrNull(lookup.meta(), KeyMeta.class);
            KeyState state = json.readOrNull(lookup.payload(), KeyState.class);
            if (meta == null || state == null) throw ApiException.unauthorized();
            if (!state.valid() || state.exp() != null && state.exp() <= Instant.now().getEpochSecond()) {
                throw ApiException.unauthorized();
            }
            return used(Long.parseLong(meta.a()), meta.k());
        }
        var row = accounts.findApiKeyByHash(hash).orElseThrow(ApiException::unauthorized);
        if (lookup.status() == CacheLookupStatus.NONE) {
            cache.putApiKey(hash, json.write(new KeyMeta(String.valueOf(row.applicationId()), row.keyId())));
        }
        if (lookup.status() == CacheLookupStatus.MISS) {
            Long exp = row.expiresAt() == null ? null : row.expiresAt().getEpochSecond();
            cache.storePayload(lookup.storeKey(), json.write(new KeyState(row.valid(), exp)), CacheGateway.DEFAULT_TTL_SECONDS);
        }
        if (!row.valid()) throw ApiException.unauthorized();
        return used(row.applicationId(), row.keyId());
    }

    @Override
    @Scheduled(initialDelay = 60_000, fixedDelay = 60_000)
    public void flushKeyUsage() {
        if (usedKeys.isEmpty()) return;
        var ids = new ArrayList<>(usedKeys);
        usedKeys.removeAll(ids);
        try {
            accounts.markKeysUsed(ids);
        } catch (DataAccessException e) {
            log.warn("Could not record API key usage: {}", e.getClass().getSimpleName());
        }
    }

    @Override
    public int purgeSessions() {
        return accounts.purgeSessions(idleMinutes, 5000);
    }

    @Override
    public AdminPrincipal principal(String username) {
        return DddBoundary.execute(() -> {
            var account = accounts.findAccountByUsername(username)
                    .orElseThrow(() -> DomainException.missing("管理员账号不存在"));
            return principal(account.id(), account.username(), account.displayName(), account.role(),
                    account.kind(), account.root(), account.scope().allDepartments(), account.scope().allApplications());
        });
    }

    @Override
    public List<Map<String, Object>> accounts(AdminPrincipal actor) {
        var tree = hierarchy();
        var applications = new HashMap<Long, List<Long>>();
        for (var pair : accounts.accountApplicationPairs()) {
            applications.computeIfAbsent((Long) pair.get("accountId"), k -> new ArrayList<>())
                    .add(((Number) pair.get("application_id")).longValue());
        }
        var departments = new HashMap<Long, List<Long>>();
        for (var pair : accounts.accountDepartmentPairs()) {
            departments.computeIfAbsent((Long) pair.get("accountId"), k -> new ArrayList<>())
                    .add(((Number) pair.get("department_id")).longValue());
        }
        var result = new ArrayList<Map<String, Object>>();
        for (var account : accounts.listAccountRows()) {
            long id = (Long) account.get("id");
            boolean manageable = tree.manages(actor.id(), id);
            if (!manageable && id != actor.id()) continue;
            account.put("applicationIds", applications.getOrDefault(id, List.of()));
            account.put("departmentIds", departments.getOrDefault(id, List.of()));
            account.put("manageable", manageable);
            result.add(account);
        }
        return result;
    }

    @Override
    @Transactional
    public long createAccount(Requests.Account input, AdminPrincipal actor) {
        return DddBoundary.execute(() -> {
            accounts.lockAllAccounts();
            requireRole(input.role());
            var tree = hierarchy();
            long parentId = requestedParent(input.parentId(), input.parentUsername(), actor.id());
            var parent = tree.node(parentId);
            if (parent == null) throw DomainException.bad("上级管理员不存在");
            if (parentId != actor.id() && !tree.manages(actor.id(), parentId)) {
                throw DomainException.forbidden("只能在自己或自己管理的管理员下创建账号");
            }
            String kind = input.kind() == null ? AdminPrincipal.MANAGER : input.kind();
            boolean allDepartments = everything(input.allDepartments(), input.departmentIds());
            var departments = allDepartments ? List.<Long>of() : resolveDepartments(input.departmentIds());
            boolean allApplications = everything(input.allApplications(), input.applicationIds());
            var applications = allApplications ? List.<Long>of() : resolveApplications(input.applicationIds());
            boolean enabled = !Boolean.FALSE.equals(input.enabled());
            var scope = new AdminScope(allDepartments, Set.copyOf(departments), allApplications, Set.copyOf(applications));
            var candidate = new AdminHierarchy.AdminNode(0, input.username(), parentId, kind, input.role(), enabled, scope);
            tree.validateCreate(actor.id(), candidate);
            PasswordPolicy.validateAdminPasswordBytes(input.password());

            String displayName = blankTo(input.displayName(), input.username());
            long id = accounts.createAccount(input.username(), displayName, input.role(),
                    crypto.encodeAdminPassword(input.password()), enabled, parentId, kind, allDepartments, allApplications);
            accounts.replaceAccountApplications(id, applications);
            accounts.replaceAccountDepartments(id, departments);
            rbac.audit(actor.actor(), "ACCOUNT_CREATED", input.username(), null, null,
                    "角色 " + input.role() + "，上级 " + parent.username() + kindDetail(kind) + scope.auditDetail());
            return id;
        });
    }

    @Override
    @Transactional
    public void updateAccount(long id, Requests.AccountUpdate input, AdminPrincipal actor) {
        DddBoundary.run(() -> {
            accounts.lockAllAccounts();
            var tree = hierarchy();
            var current = tree.node(id);
            if (current == null) throw DomainException.missing("管理员账号不存在");
            if (id != actor.id() && !tree.manages(actor.id(), id)) {
                throw DomainException.forbidden("只能管理自己下级的管理员账号");
            }
            requireRole(input.role());
            String kind = input.kind() == null ? current.kind() : input.kind();
            boolean keepDepartments = input.allDepartments() == null && input.departmentIds() == null;
            boolean allDepartments = keepDepartments ? current.scope().allDepartments()
                    : everything(input.allDepartments(), input.departmentIds());
            var departments = allDepartments ? List.<Long>of()
                    : keepDepartments ? List.copyOf(current.scope().departments()) : resolveDepartments(input.departmentIds());
            boolean keepApplications = input.allApplications() == null && input.applicationIds() == null;
            boolean allApplications = keepApplications ? current.scope().allApplications()
                    : everything(input.allApplications(), input.applicationIds());
            var applications = allApplications ? List.<Long>of()
                    : keepApplications ? List.copyOf(current.scope().applications()) : resolveApplications(input.applicationIds());
            Long parentId = requestedParent(input.parentId(), input.parentUsername(), current.parentId());
            var nextScope = new AdminScope(allDepartments, Set.copyOf(departments), allApplications, Set.copyOf(applications));
            var proposed = new AdminHierarchy.AdminNode(id, current.username(), parentId, kind, input.role(), input.enabled(), nextScope);
            var decision = tree.validateUpdate(actor.id(), proposed);

            accounts.updateAccount(id, blankTo(input.displayName(), current.username()), input.role(), input.enabled(),
                    kind, allDepartments, allApplications);
            accounts.replaceAccountApplications(id, applications);
            accounts.replaceAccountDepartments(id, departments);
            if (decision.parentChanged()) accounts.moveAccountUnder(id, parentId);
            if (decision.revokeSessions()) accounts.endAllSessions(id);
            rbac.audit(actor.actor(), "ACCOUNT_UPDATED", current.username(), null, null,
                    "角色 " + input.role() + (input.enabled() ? "，启用" : "，停用")
                            + (decision.parentChanged() ? "，上级改为 " + decision.newParent().username() : "")
                            + kindDetail(kind) + nextScope.auditDetail());
        });
    }

    @Override
    @Transactional
    public void resetPassword(long id, Requests.PasswordReset input, AdminPrincipal actor) {
        DddBoundary.run(() -> {
            accounts.lockAllAccounts();
            String username = hierarchy().requireManaged(actor.id(), id).username();
            PasswordPolicy.validateAdminPasswordBytes(input.password());
            if (accounts.updatePassword(id, crypto.encodeAdminPassword(input.password())) == 0) {
                throw DomainException.missing("管理员账号不存在");
            }
            accounts.endAllSessions(id);
            rbac.audit(actor.actor(), "ACCOUNT_PASSWORD_RESET", username, null, null, "该账号全部会话已下线");
        });
    }

    @Override
    @Transactional
    public void unlock(long id, AdminPrincipal actor) {
        DddBoundary.run(() -> {
            accounts.lockAllAccounts();
            String username = hierarchy().requireManaged(actor.id(), id).username();
            if (accounts.unlockAccount(id) == 0) throw DomainException.missing("管理员账号不存在");
            rbac.audit(actor.actor(), "ACCOUNT_UNLOCKED", username, null, null, "");
        });
    }

    @Override
    @Transactional
    public void deleteAccount(long id, AdminPrincipal actor) {
        DddBoundary.run(() -> {
            if (id == actor.id()) throw DomainException.bad("不能删除当前登录的账号");
            accounts.lockAllAccounts();
            var target = hierarchy().validateDelete(actor.id(), id);
            if (accounts.deleteAccount(id) == 0) throw DomainException.missing("管理员账号不存在");
            rbac.audit(actor.actor(), "ACCOUNT_DELETED", target.username(), null, null, "");
        });
    }

    @Override
    public void lockTree() {
        accounts.lockAllAccounts();
    }

    @Override
    public void requireConsistentWithRole(String role, Set<String> functions) {
        DddBoundary.run(() -> hierarchy().requireConsistentWithRoleChange(role, functions));
    }

    private AdminHierarchy hierarchy() {
        return new AdminHierarchy(accounts.loadHierarchyNodes(), roles.functionsByRole());
    }

    private AdminPrincipal principal(long id, String username, String displayName, String role, String kind,
                                     boolean root, boolean allDepartments, boolean allApplications) {
        var granted = roles.findRole(role).orElseThrow(ApiException::unauthorized);
        var functions = EnumSet.noneOf(AdminFunction.class);
        granted.functions().stream().map(AdminFunction::of).filter(Objects::nonNull).forEach(functions::add);
        Set<Long> departments = allDepartments ? Set.of() : Set.copyOf(accounts.accountDepartments(id));
        Set<Long> applications = allApplications ? Set.of() : Set.copyOf(accounts.accountApplications(id));
        return new AdminPrincipal(id, username, blankTo(displayName, username), role, granted.name(),
                Collections.unmodifiableSet(functions), root, kind, allDepartments, departments, allApplications, applications);
    }

    private void requireRole(String role) {
        if (!roles.roleExists(role)) throw DomainException.bad("管理员角色不存在");
    }

    private static boolean everything(Boolean requested, List<Long> listed) {
        return requested != null ? requested : listed == null;
    }

    private List<Long> resolveApplications(List<Long> requested) {
        if (requested == null) return List.of();
        var ids = new ArrayList<>(new LinkedHashSet<>(requested));
        if (accounts.countExistingApplications(ids) != ids.size()) throw DomainException.missing("授权的软件不存在");
        return ids;
    }

    private List<Long> resolveDepartments(List<Long> requested) {
        if (requested == null) return List.of();
        var ids = new ArrayList<>(new LinkedHashSet<>(requested));
        if (accounts.countExistingDepartments(ids) != ids.size()) throw DomainException.missing("指定的部门不存在");
        return ids;
    }

    private Long requestedParent(Long requestedId, String requestedUsername, Long fallback) {
        if (requestedId != null) return requestedId;
        if (requestedUsername == null) return fallback;
        return accounts.findAccountByUsername(requestedUsername).map(AdminCredentialAccount::id)
                .orElseThrow(() -> DomainException.bad("上级管理员不存在"));
    }

    private ApplicationCaller used(long application, long key) {
        usedKeys.add(key);
        return new ApplicationCaller(application, key);
    }

    private static String kindDetail(String kind) {
        return AdminPrincipal.DEPARTMENT.equals(kind) ? "，部门管理员" : "";
    }

    private static String blankTo(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.strip();
    }

    private static DomainException badCredentials() {
        return DomainException.unauthorized("BAD_CREDENTIALS", "用户名或密码错误");
    }

    private DomainException locked() {
        return DomainException.forbidden("ACCOUNT_LOCKED",
                "登录失败次数过多，账号已锁定 " + lockMinutes + " 分钟，可联系超级管理员解锁");
    }
}
