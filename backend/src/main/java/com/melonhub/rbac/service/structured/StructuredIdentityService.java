package com.melonhub.rbac.service.structured;

import com.melonhub.rbac.identity.IdentityTokenService;
import com.melonhub.rbac.service.port.IdentityUseCase;
import com.melonhub.rbac.service.port.RbacUseCase;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import com.melonhub.rbac.dao.IdentityDao;
import com.melonhub.rbac.dao.RbacDao;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.security.AdminFunction;
import com.melonhub.rbac.security.AdminPrincipal;
import com.melonhub.rbac.security.Credentials;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 统一身份认证与课程系统权限查询应用服务。
 */
@Service
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "structured", matchIfMissing = true)
public class StructuredIdentityService implements IdentityUseCase {

    private static final String COURSE_SYSTEM = "course-project-management";
    private static final String COURSE_AUDIT_VIEW = "AV";
    private static final Map<String, String> API_PERMISSION_CODES = Map.ofEntries(
            Map.entry("listTerms", "CV"),
            Map.entry("createTerm", "TC"),
            Map.entry("updateTerm", "TE"),
            Map.entry("deleteTerm", "TD"),
            Map.entry("setCurrentTerm", "TCM"),
            Map.entry("cancelCurrentTerm", "TCM"),
            Map.entry("getCourse", "CV"),
            Map.entry("createCourse", "CE"),
            Map.entry("submitCourseReview", "CR"),
            Map.entry("reviewCourse", "CR"),
            Map.entry("updateCourse", "CE"),
            Map.entry("deleteCourse", "CD"),
            Map.entry("copyCourse", "CC"),
            Map.entry("setCourseLeaders", "CTM"),
            Map.entry("listAdminCourses", "CV"),
            Map.entry("listTeachers", "TV"),
            Map.entry("createTeacher", "TEC"),
            Map.entry("updateTeacher", "TEE"),
            Map.entry("deleteTeacher", "TED"),
            Map.entry("queryAuditLogs", COURSE_AUDIT_VIEW),
            Map.entry("listAuditLogs", COURSE_AUDIT_VIEW)
    );

    private final IdentityDao identityDao;
    private final RbacUseCase rbacService;
    private final PasswordEncoder passwordEncoder;
    private final IdentityTokenService tokenService;

    /**
     * 创建统一身份服务。
     *
     * @param identityDao 统一身份持久化端口
     * @param rbacService RBAC 授权服务
     * @param passwordEncoder 密码编码器
     * @param tokenService JWT 服务
     */
    public StructuredIdentityService(
            IdentityDao identityDao,
            RbacUseCase rbacService,
            PasswordEncoder passwordEncoder,
            IdentityTokenService tokenService
    ) {
        this.identityDao = identityDao;
        this.rbacService = rbacService;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
    }

    /**
     * 登录并签发 JWT。
     *
     * @param username 登录名
     * @param password 明文密码，仅在当前调用栈中使用
     * @param systems 目标系统
     * @return 登录响应
     */
    @Transactional
    public Map<String, Object> login(String username, String password, List<String> systems) {
        if (systems == null || systems.isEmpty() || !systems.contains(COURSE_SYSTEM)) {
            throw ApiException.bad("systems 必须包含 course-project-management");
        }
        IdentityDao.CredentialRow credential = identityDao.credential(username)
                .orElseThrow(() -> new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "账号或密码错误。"));
        if (!passwordEncoder.matches(password, credential.passwordHash())) {
            throw new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "账号或密码错误。");
        }
        Instant issuedAt = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        String token = tokenService.issue(credential.username(), systems, issuedAt);
        IdentityTokenService.Claims claims = tokenService.verify(token, COURSE_SYSTEM);
        if (!identityDao.createSession(Credentials.hash(token), credential, COURSE_SYSTEM, claims.expiresAt())) {
            throw new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "账号或密码错误。");
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("accessToken", token);
        response.put("tokenType", "Bearer");
        response.put("expiresIn", claims.expiresAt().getEpochSecond() - issuedAt.getEpochSecond());
        return response;
    }

    /** 查询当前课程账号具有 AV 权限的部门内的业务日志。 */
    @Transactional(readOnly = true)
    public Map<String, Object> auditLogs(String authorization, String actor, Long actorId, String target,
                                        OffsetDateTime from, OffsetDateTime to, int page, int pageSize) {
        IdentityDao.UserRow user = authenticatedUser(authorization);
        List<Long> departments = identityDao.permissionDepartments(user.id(), COURSE_SYSTEM, COURSE_AUDIT_VIEW);
        if (departments.isEmpty()) {
            throw ApiException.forbidden("你没有查看课程日志的权限。");
        }
        RbacDao.Page events = identityDao.courseAuditEvents(COURSE_SYSTEM, departments, actor, actorId, target,
                from == null ? null : from.toInstant(), to == null ? null : to.toInstant(), page, pageSize);
        List<Long> actorIds = events.items().stream().map(row -> (Long) row.get("actorId"))
                .filter(Objects::nonNull).distinct().toList();
        Map<Long, List<String>> roles = identityDao.auditActorRoles(actorIds, COURSE_SYSTEM, departments);
        List<Map<String, Object>> items = events.items().stream().map(row -> auditItem(row, roles)).toList();
        return page(page, pageSize, events.total(), items);
    }

    /** 使用已有的操作人资料，并为已删除或无法关联的标识保留历史显示。 */
    private static Map<String, Object> auditItem(Map<String, Object> row, Map<Long, List<String>> roles) {
        Long id = (Long) row.get("actorId");
        Map<String, Object> actor = new LinkedHashMap<>();
        actor.put("id", id);
        actor.put("name", id == null ? row.get("actorNo") : row.get("actorName"));
        actor.put("roles", id == null ? List.of() : roles.getOrDefault(id, List.of()));
        actor.put("deleted", id == null);
        return Map.of("id", row.get("id"), "at", ((Timestamp) row.get("at")).toInstant().toString(),
                "actor", actor, "type", row.get("type"), "target", row.get("target"));
    }

    /**
     * 撤销当前令牌。
     *
     * @param authorization Authorization 请求头
     */
    @Transactional
    public void logout(String authorization) {
        String token = bearerToken(authorization);
        tokenService.verify(token, COURSE_SYSTEM);
        identityDao.revokeSession(Credentials.hash(token), Instant.now());
    }

    /**
     * 查询当前身份、角色和前端权限。
     *
     * @param authorization Authorization 请求头
     * @return 当前用户响应
     */
    @Transactional(readOnly = true)
    public Map<String, Object> currentUser(String authorization) {
        IdentityTokenService.Claims claims = authenticated(authorization);
        IdentityDao.UserRow user = identityDao.userByExternalId(claims.subject())
                .orElseThrow(() -> new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "请先登录。"));
        List<String> roles = identityDao.roles(user.id(), COURSE_SYSTEM).stream()
                .map(value -> value.toLowerCase(Locale.ROOT))
                .toList();
        List<String> permissions = identityDao.permissions(user.id(), COURSE_SYSTEM);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("subject", user.externalId());
        response.put("roles", roles);
        response.put("permissions", permissions);
        response.put("name", user.name());
        response.put("no", user.externalId());
        return response;
    }

    /**
     * 查询组织部门。
     *
     * @param authorization Authorization 请求头
     * @param keyword 关键字
     * @param parentId 父部门
     * @param page 页码
     * @param pageSize 页大小
     * @return 分页结果
     */
    @Transactional(readOnly = true)
    public Map<String, Object> departments(String authorization, String keyword, Long parentId, int page, int pageSize) {
        IdentityDao.UserRow user = authenticatedUser(authorization);
        requirePermission(user.id(), "ORG_VIEW");
        List<IdentityDao.DepartmentRow> rows = identityDao.departments(keyword, parentId, page, pageSize);
        List<Map<String, Object>> items = new ArrayList<>();
        for (IdentityDao.DepartmentRow row : rows) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", row.id());
            item.put("code", row.code());
            item.put("name", row.name());
            item.put("parentId", row.parentId());
            item.put("hasChildren", row.hasChildren());
            items.add(item);
        }
        return page(page, pageSize, identityDao.departmentCount(keyword, parentId), items);
    }

    /**
     * 查询部门用户。
     *
     * @param authorization Authorization 请求头
     * @param departmentId 部门主键
     * @param keyword 关键字
     * @param page 页码
     * @param pageSize 页大小
     * @return 分页结果
     */
    @Transactional(readOnly = true)
    public Map<String, Object> departmentUsers(String authorization, long departmentId, String keyword, int page, int pageSize) {
        IdentityDao.UserRow user = authenticatedUser(authorization);
        requirePermission(user.id(), "ORG_VIEW");
        if (!identityDao.departmentExists(departmentId)) {
            throw new ApiException(org.springframework.http.HttpStatus.NOT_FOUND, "IDENTITY_DEPARTMENT_NOT_FOUND", "统一身份认证系统中没有找到该部门。");
        }
        List<IdentityDao.DepartmentUserRow> rows = identityDao.departmentUsers(departmentId, keyword, page, pageSize);
        List<Map<String, Object>> items = new ArrayList<>();
        for (IdentityDao.DepartmentUserRow row : rows) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("userId", row.userId());
            item.put("no", row.no());
            item.put("name", row.name());
            item.put("departmentId", row.departmentId());
            item.put("departmentName", row.departmentName());
            items.add(item);
        }
        return page(page, pageSize, identityDao.departmentUserCount(departmentId, keyword), items);
    }

    /**
     * 校验前端菜单或按钮权限。
     *
     * @param authorization Authorization 请求头
     * @param permission 权限编码
     * @return 是否允许
     */
    @Transactional(readOnly = true)
    public Map<String, Object> checkPermission(String authorization, String permission) {
        IdentityDao.UserRow user = authenticatedUser(authorization);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("allowed", identityDao.permissions(user.id(), COURSE_SYSTEM).contains(permission));
        return response;
    }

    /**
     * 校验课程系统 API 的全局权限。
     *
     * @param authorization Authorization 请求头
     * @param operationId OpenAPI operationId
     * @return 是否允许
     */
    @Transactional(readOnly = true)
    public Map<String, Object> checkApiPermission(String authorization, String operationId) {
        IdentityDao.UserRow user = authenticatedUser(authorization);
        String permission = API_PERMISSION_CODES.get(operationId);
        if (permission == null) {
            throw new ApiException(org.springframework.http.HttpStatus.NOT_FOUND, "API_OPERATION_NOT_FOUND", "没有找到对应的 API 操作。");
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("operationId", operationId);
        response.put("allowed", identityDao.permissions(user.id(), COURSE_SYSTEM).contains(permission));
        return response;
    }

    /**
     * 查询统一身份用户。
     *
     * @param authorization Authorization 请求头
     * @param userId 外部用户标识
     * @return 用户信息
     */
    @Transactional(readOnly = true)
    public Map<String, Object> lookupUser(String authorization, String userId) {
        IdentityDao.UserRow current = authenticatedUser(authorization);
        requirePermission(current.id(), "TEC");
        IdentityDao.UserRow user = identityDao.userByExternalId(userId)
                .orElseThrow(() -> new ApiException(org.springframework.http.HttpStatus.NOT_FOUND, "IDENTITY_USER_NOT_FOUND", "统一身份认证系统中没有找到该用户。"));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("userId", user.externalId());
        response.put("no", user.externalId());
        response.put("name", user.name());
        return response;
    }

    /**
     * 创建或更新一个可登录的统一身份用户。
     *
     * @param body 用户资料
     * @param actor 操作人
     * @return 用户主键
     */
    @Transactional
    public long provisionUser(Requests.User body, String password, String actor) {
        Long existingId = identityDao.userByExternalId(body.externalId()).map(IdentityDao.UserRow::id).orElse(null);
        long userId = rbacService.user(body, existingId, actor);
        savePassword(userId, body.externalId(), password, actor);
        return userId;
    }

    @Transactional
    public long createUser(Requests.UserCreate body, AdminPrincipal principal) {
        if (body.identityPassword() != null && !principal.canUse(AdminFunction.USER_CREDENTIALS)) {
            throw ApiException.forbidden("当前账号没有管理用户登录凭据功能");
        }
        long userId = rbacService.user(body.profile(), null, principal.actor(), principal.visibleDepartments());
        if (body.identityPassword() != null) {
            savePassword(userId, body.externalId(), body.identityPassword(), principal.actor());
        }
        return userId;
    }

    @Transactional
    public void setUserPassword(long userId, String password, AdminPrincipal principal) {
        String username = rbacService.lockOwnedUser(userId, principal.visibleDepartments());
        savePassword(userId, username, password, principal.actor());
    }

    private void savePassword(long userId, String username, String password, String actor) {
        if (password.isBlank() || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw ApiException.bad("统一身份密码不能为空，且 UTF-8 长度不能超过 72 字节");
        }
        identityDao.upsertCredential(userId, username, passwordEncoder.encode(password));
        identityDao.revokeUserSessions(userId);
        rbacService.audit(actor, "USER_IDENTITY_PASSWORD_SET", username, null, null, "统一身份会话已结束");
    }

    private IdentityTokenService.Claims authenticated(String authorization) {
        String token = bearerToken(authorization);
        IdentityTokenService.Claims claims = tokenService.verify(token, COURSE_SYSTEM);
        if (!identityDao.activeSession(Credentials.hash(token), Instant.now())) {
            throw new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "请先登录或令牌已失效。");
        }
        return claims;
    }

    private IdentityDao.UserRow authenticatedUser(String authorization) {
        IdentityTokenService.Claims claims = authenticated(authorization);
        return identityDao.userByExternalId(claims.subject())
                .orElseThrow(() -> new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "请先登录。"));
    }

    private void requirePermission(long userId, String permission) {
        List<String> permissions = identityDao.permissions(userId, COURSE_SYSTEM);
        List<String> roles = identityDao.roles(userId, COURSE_SYSTEM);
        if (!permissions.contains(permission) && !roles.contains("admin")) {
            throw ApiException.forbidden("你没有查询统一身份组织架构的权限。");
        }
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ") || authorization.length() <= 7) {
            throw new ApiException(org.springframework.http.HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "请先登录。");
        }
        return authorization.substring(7).trim();
    }

    private static Map<String, Object> page(int page, int pageSize, long total, List<Map<String, Object>> items) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("page", page);
        response.put("pageSize", pageSize);
        response.put("total", total);
        response.put("items", items);
        return response;
    }
}
