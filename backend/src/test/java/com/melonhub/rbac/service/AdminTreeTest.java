package com.melonhub.rbac.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.melonhub.rbac.dao.AuthDao.AccountNode;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AdminTreeTest {
    private static final Map<String,Set<String>> ROLES = Map.of(
            "SUPER_ADMIN", Set.of("org.view", "domain.view", "domain.assign", "account.manage", "role.manage"),
            "MANAGER_ROLE", Set.of("org.view", "domain.view", "domain.assign", "account.manage"),
            "DEPT_ROLE", Set.of("org.view", "domain.view", "domain.assign"));

    private static AccountNode manager(long id, String name, Long parentId, String role, Set<Long> departments) {
        return new AccountNode(id, name, parentId, "MANAGER", role, true, departments == null, departments == null ? Set.of() : departments, true, Set.of());
    }
    private static AccountNode department(long id, String name, Long parentId, String role, Set<Long> departments) {
        return new AccountNode(id, name, parentId, "DEPARTMENT", role, true, false, departments, true, Set.of());
    }

    @Test void rootsManageEveryoneAndManagersTheirSubtree() {
        var tree = new AdminTree(List.of(
                manager(1L, "root", null, "SUPER_ADMIN", null),
                manager(2L, "east", 1L, "MANAGER_ROLE", Set.of(1L, 2L)),
                department(3L, "sales", 2L, "DEPT_ROLE", Set.of(1L)),
                manager(4L, "west", 1L, "MANAGER_ROLE", Set.of(3L))), ROLES);
        assertThat(tree.violations()).isEmpty();
        assertThat(tree.descendants(1L)).containsExactlyInAnyOrder(2L, 3L, 4L);
        assertThat(tree.manages(1L, 4L)).isTrue();
        assertThat(tree.manages(2L, 3L)).isTrue();
        assertThat(tree.manages(2L, 4L)).isFalse();
        assertThat(tree.manages(2L, 1L)).isFalse();
        assertThat(tree.manages(3L, 2L)).isFalse();
        assertThat(tree.manages(1L, 1L)).isFalse();
    }

    @Test void aChildNeverExceedsItsParent() {
        var tree = new AdminTree(List.of(
                manager(1L, "root", null, "SUPER_ADMIN", null),
                manager(2L, "east", 1L, "MANAGER_ROLE", Set.of(1L, 2L)),
                department(5L, "wide", 2L, "DEPT_ROLE", Set.of(1L, 3L)),
                manager(6L, "everywhere", 2L, "DEPT_ROLE", null),
                manager(7L, "stronger", 2L, "SUPER_ADMIN", Set.of(1L))), ROLES);
        assertThat(tree.violations()).hasSize(3)
                .anyMatch(p -> p.startsWith("wide：部门范围超出上级"))
                .anyMatch(p -> p.startsWith("everywhere：部门范围超出上级"))
                .anyMatch(p -> p.startsWith("stronger：角色功能超出上级"));
    }

    @Test void departmentAdministratorsAreLimitedLeavesWithoutAccountManagement() {
        var tree = new AdminTree(List.of(
                manager(1L, "root", null, "SUPER_ADMIN", null),
                department(8L, "unlimited", 1L, "DEPT_ROLE", Set.of()),
                department(9L, "delegating", 1L, "MANAGER_ROLE", Set.of(1L)),
                department(10L, "parent", 1L, "DEPT_ROLE", Set.of(1L)),
                department(11L, "child", 10L, "DEPT_ROLE", Set.of(1L))), ROLES);
        assertThat(tree.violations())
                .anyMatch(p -> p.startsWith("unlimited：部门管理员必须指定所管理的部门"))
                .anyMatch(p -> p.startsWith("delegating：部门管理员不能拥有管理管理员账号或角色的功能"))
                .anyMatch(p -> p.startsWith("parent：部门管理员不能有下级管理员"));
    }

    @Test void parentChainsMustEndAtARoot() {
        var tree = new AdminTree(List.of(
                manager(12L, "a", 13L, "DEPT_ROLE", null),
                manager(13L, "b", 12L, "DEPT_ROLE", null),
                manager(14L, "orphan", 15L, "DEPT_ROLE", null)), ROLES);
        assertThat(tree.violations()).contains("a：上级关系形成循环", "b：上级关系形成循环", "orphan：上级管理员不存在");
    }
}
