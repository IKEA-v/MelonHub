package com.melonhub.rbac.service.port;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.AdminPrincipal;
import java.util.List;
import java.util.Map;

/**
 * 控制台管理员功能清单与自定义管理员角色维护用例端口。
 */
public interface AdminRoleUseCase {
    List<Map<String, Object>> functions();

    List<Map<String, Object>> roles();

    void create(Requests.AdminRoleCreate input, AdminPrincipal actor);

    void update(String code, Requests.AdminRoleUpdate input, AdminPrincipal actor);

    void delete(String code, AdminPrincipal actor);
}
