package com.melonhub.rbac.service.ddd.infrastructure;

import com.melonhub.rbac.dao.AdminRoleDao;
import com.melonhub.rbac.service.ddd.domain.model.AdminRoleAggregate;
import com.melonhub.rbac.service.ddd.domain.repository.AdminRoleRepositoryPort;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** DDD 基础设施适配器：将 {@link AdminRoleRepositoryPort} 桥接到 {@link AdminRoleDao}。 */
@Component
@ConditionalOnProperty(name = "melonhub.backend-strategy", havingValue = "ddd")
public class JpaAdminRoleRepositoryAdapter implements AdminRoleRepositoryPort {
    private final AdminRoleDao dao;

    public JpaAdminRoleRepositoryAdapter(AdminRoleDao dao) {
        this.dao = dao;
    }

    @Override public List<Map<String, Object>> functions() { return dao.functions(); }
    @Override public List<Map<String, Object>> roles() { return dao.roles(); }
    @Override public Optional<AdminRoleAggregate> findRole(String code) {
        return dao.role(code).map(r -> new AdminRoleAggregate(r.code(), r.name(), "", r.builtin(), r.functions()));
    }
    @Override public boolean roleExists(String code) { return dao.exists(code); }
    @Override public Map<String, Set<String>> functionsByRole() { return dao.functionsByRole(); }
    @Override public long countAccountsUsingRole(String code) { return dao.accounts(code); }
    @Override public void createRole(String code, String name, String description, Collection<String> functions) {
        dao.create(code, name, description, functions);
    }
    @Override public void updateRole(String code, String name, String description, Collection<String> functions) {
        dao.update(code, name, description, functions);
    }
    @Override public int deleteRole(String code) {
        dao.delete(code);
        return 1;
    }
}
