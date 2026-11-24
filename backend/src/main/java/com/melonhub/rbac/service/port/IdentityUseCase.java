package com.melonhub.rbac.service.port;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.AdminPrincipal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * 面向课程管理系统的统一身份认证、权限判定、组织架构与课程审计日志用例端口。
 */
public interface IdentityUseCase {
    Map<String, Object> login(String username, String password, List<String> systems);

    Map<String, Object> auditLogs(String authorization, String actor, Long actorId, String target,
                                  OffsetDateTime from, OffsetDateTime to, int page, int pageSize);

    void logout(String authorization);

    Map<String, Object> currentUser(String authorization);

    Map<String, Object> departments(String authorization, String keyword, Long parentId, int page, int pageSize);

    Map<String, Object> departmentUsers(String authorization, long departmentId, String keyword, int page, int pageSize);

    Map<String, Object> checkPermission(String authorization, String permission);

    Map<String, Object> checkApiPermission(String authorization, String operationId);

    Map<String, Object> lookupUser(String authorization, String userId);

    long provisionUser(Requests.User body, String password, String actor);

    long createUser(Requests.UserCreate body, AdminPrincipal principal);

    void setUserPassword(long userId, String password, AdminPrincipal principal);
}
