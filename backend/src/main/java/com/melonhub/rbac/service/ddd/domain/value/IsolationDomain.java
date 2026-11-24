package com.melonhub.rbac.service.ddd.domain.value;

/**
 * 授权隔离域值对象：部门 × 软件二维边界。
 */
public record IsolationDomain(long departmentId, long applicationId) {
    public IsolationDomain {
        if (departmentId < 1 || applicationId < 1) {
            throw DomainException.bad("隔离域的部门和软件标识必须为正整数");
        }
    }
}
