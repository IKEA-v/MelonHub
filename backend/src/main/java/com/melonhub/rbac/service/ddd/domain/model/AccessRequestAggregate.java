package com.melonhub.rbac.service.ddd.domain.model;

import com.melonhub.rbac.service.ddd.domain.value.DomainException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;

/**
 * 角色访问申请聚合根：封装申请状态机（PENDING -> APPROVED / REJECTED / CANCELLED）、
 * 永久授权与天数互斥校验、目标对象存在性与角色启用状态检查。
 */
public final class AccessRequestAggregate {
    public static final List<String> VALID_STATUSES = List.of("PENDING", "APPROVED", "REJECTED", "CANCELLED");

    public record ApprovalPlan(
            long userId,
            long departmentId,
            long applicationId,
            long roleId,
            String externalId,
            String roleCode,
            Integer grantedDays,
            Instant expiresAt,
            String comment
    ) {
        public String auditDetail() {
            return "角色 " + roleCode + (grantedDays == null ? "，永久授权" : "，" + grantedDays + " 天有效");
        }
    }

    private final long id;
    private final String status;
    private final Long userId;
    private final Long departmentId;
    private final long applicationId;
    private final Long roleId;
    private final boolean roleEnabled;
    private final String externalId;
    private final String roleCode;
    private final Integer requestedDurationDays;

    public AccessRequestAggregate(long id, String status, Long userId, Long departmentId, long applicationId,
                                  Long roleId, boolean roleEnabled, String externalId, String roleCode,
                                  Integer requestedDurationDays) {
        this.id = id;
        this.status = status;
        this.userId = userId;
        this.departmentId = departmentId;
        this.applicationId = applicationId;
        this.roleId = roleId;
        this.roleEnabled = roleEnabled;
        this.externalId = externalId;
        this.roleCode = roleCode;
        this.requestedDurationDays = requestedDurationDays;
    }

    public static void validateStatusFilter(String status) {
        if (status != null && !status.isBlank() && !VALID_STATUSES.contains(status.strip())) {
            throw DomainException.bad("状态只能是 PENDING、APPROVED、REJECTED 或 CANCELLED");
        }
    }

    public static void validateSubmission(boolean memberOfDepartment, boolean roleInDomain, boolean pendingExists) {
        if (!memberOfDepartment) throw DomainException.forbidden("用户不属于目标部门");
        if (!roleInDomain) throw DomainException.missing("角色不存在于该隔离域");
        if (pendingExists) throw DomainException.conflict("该用户已有此角色的待审批申请");
    }

    public ApprovalPlan planApproval(Boolean permanentFlag, Integer overrideDays, String comment, Instant now) {
        if (!"PENDING".equals(status)) {
            throw DomainException.conflict("申请已被处理");
        }
        if (userId == null || roleId == null || departmentId == null) {
            throw DomainException.conflict("申请涉及的用户、角色或部门已删除");
        }
        if (!roleEnabled) {
            throw DomainException.conflict("角色已停用，无法授权");
        }
        boolean permanent = Boolean.TRUE.equals(permanentFlag);
        if (permanent && overrideDays != null) {
            throw DomainException.bad("永久授权时不能同时指定天数");
        }
        Integer days = permanent ? null : (overrideDays != null ? overrideDays : requestedDurationDays);
        Instant expiresAt = days == null ? null : now.truncatedTo(ChronoUnit.SECONDS).plus(days, ChronoUnit.DAYS);
        return new ApprovalPlan(userId, departmentId, applicationId, roleId, externalId, roleCode,
                days, expiresAt, clean(comment));
    }

    public void assertRejectable() {
        if (!"PENDING".equals(status)) {
            throw DomainException.conflict("申请已被处理");
        }
    }

    public void assertOwnedByApplicant(long callingAppId, long applicantUserId) {
        if (applicationId != callingAppId || !Objects.equals(userId, applicantUserId)) {
            throw DomainException.missing("申请不存在");
        }
    }

    public long id() { return id; }
    public Long userId() { return userId; }
    public Long departmentId() { return departmentId; }
    public long applicationId() { return applicationId; }
    public Long roleId() { return roleId; }
    public String externalId() { return externalId; }
    public String roleCode() { return roleCode; }

    private static String clean(String value) {
        return Objects.requireNonNullElse(value, "").strip();
    }
}
