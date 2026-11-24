package com.melonhub.rbac.service.ddd.domain.repository;

import com.melonhub.rbac.service.ddd.domain.model.AdminRoleAggregate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 控制台管理员功能目录与自定义管理员角色领域仓储端口。
 */
public interface AdminRoleRepositoryPort {
    List<Map<String, Object>> functions();

    List<Map<String, Object>> roles();

    Optional<AdminRoleAggregate> findRole(String code);

    boolean roleExists(String code);

    Map<String, Set<String>> functionsByRole();

    long countAccountsUsingRole(String code);

    void createRole(String code, String name, String description, Collection<String> functions);

    void updateRole(String code, String name, String description, Collection<String> functions);

    int deleteRole(String code);
}
