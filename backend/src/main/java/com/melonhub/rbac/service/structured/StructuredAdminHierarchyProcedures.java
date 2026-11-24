package com.melonhub.rbac.service.structured;

import com.melonhub.rbac.dao.AuthDao.AccountNode;
import com.melonhub.rbac.security.AdminFunction;
import com.melonhub.rbac.security.AdminPrincipal;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * 纯结构化管理员层级校验过程集：直接对 DAO 返回的 {@link AccountNode} 数据表记录集合执行静态过程函数，
 * 不构建有状态的领域聚合对象。
 */
public final class StructuredAdminHierarchyProcedures {
    private static final Set<String> ADMINISTRATION = Set.of(
            AdminFunction.ACCOUNT_MANAGE.code(),
            AdminFunction.ROLE_MANAGE.code()
    );

    private StructuredAdminHierarchyProcedures() {}

    public static AccountNode findNode(Collection<AccountNode> accounts, long id) {
        for (var node : accounts) {
            if (node.id() == id) return node;
        }
        return null;
    }

    public static List<Long> childIds(Collection<AccountNode> accounts, long id) {
        var result = new ArrayList<Long>();
        for (var node : accounts) {
            if (node.parentId() != null && node.parentId() == id) result.add(node.id());
        }
        return result;
    }

    public static Set<Long> descendantIds(Collection<AccountNode> accounts, long id) {
        var childrenByParent = indexChildren(accounts);
        var found = new TreeSet<Long>();
        var pending = new ArrayDeque<>(childrenByParent.getOrDefault(id, List.of()));
        while (!pending.isEmpty()) {
            long next = pending.poll();
            if (found.add(next)) pending.addAll(childrenByParent.getOrDefault(next, List.of()));
        }
        return found;
    }

    public static boolean manages(Collection<AccountNode> accounts, long actor, long target) {
        var byId = indexById(accounts);
        var self = byId.get(actor);
        if (self == null || actor == target || !byId.containsKey(target)) return false;
        return self.parentId() == null || descendantIds(accounts, actor).contains(target);
    }

    /** 一次线性扫描计算指定管理员可管理的全部账号 ID，避免列表展示中的 O(N²) 重复建索引。 */
    public static Set<Long> manageableAccountIds(Collection<AccountNode> accounts, long actor) {
        var byId = indexById(accounts);
        var self = byId.get(actor);
        if (self == null) return Set.of();
        if (self.parentId() == null) {
            var allOthers = new TreeSet<>(byId.keySet());
            allOthers.remove(actor);
            return allOthers;
        }
        return descendantIds(accounts, actor);
    }

    public static long enabledSuperAdminCount(Collection<AccountNode> accounts) {
        long count = 0;
        for (var node : accounts) {
            if (node.enabled() && AdminPrincipal.SUPER_ADMIN.equals(node.role())) count++;
        }
        return count;
    }

    public static List<AccountNode> replaceNode(List<AccountNode> accounts, AccountNode changed) {
        var result = new ArrayList<AccountNode>(accounts.size() + 1);
        for (var node : accounts) {
            if (node.id() != changed.id()) result.add(node);
        }
        result.add(changed);
        return result;
    }

    public static List<String> findViolations(Collection<AccountNode> accounts, Map<String, Set<String>> roleFunctions) {
        var byId = indexById(accounts);
        var childrenByParent = indexChildren(accounts);
        var problems = new ArrayList<String>();
        for (var node : byId.values()) {
            String name = node.username();
            var functions = roleFunctions.getOrDefault(node.role(), Set.of());
            if (AdminPrincipal.DEPARTMENT_ADMIN.equals(node.role())
                    && (!AdminPrincipal.DEPARTMENT.equals(node.kind()) || !node.allApplications())) {
                problems.add(name + "：内置部门管理员角色按部门划定范围，并覆盖这些部门的全部软件");
            }
            if (AdminPrincipal.DEPARTMENT.equals(node.kind())) {
                if (node.allDepartments() || node.departments().isEmpty()) {
                    problems.add(name + "：部门管理员必须指定所管理的部门");
                }
                if (functions.stream().anyMatch(ADMINISTRATION::contains)) {
                    problems.add(name + "：部门管理员不能拥有管理管理员账号或角色的功能");
                }
                if (!childrenByParent.getOrDefault(node.id(), List.of()).isEmpty()) {
                    problems.add(name + "：部门管理员不能有下级管理员");
                }
            } else if (!AdminPrincipal.MANAGER.equals(node.kind())) {
                problems.add(name + "：未知的管理员类型 " + node.kind());
            }
            if (node.parentId() == null) continue;
            var parent = byId.get(node.parentId());
            if (parent == null) {
                problems.add(name + "：上级管理员不存在");
                continue;
            }
            if (hasCycle(byId, node.id())) {
                problems.add(name + "：上级关系形成循环");
                continue;
            }
            var beyond = new TreeSet<>(functions);
            beyond.removeAll(roleFunctions.getOrDefault(parent.role(), Set.of()));
            if (!beyond.isEmpty()) {
                problems.add(name + "：角色功能超出上级 " + parent.username() + "（" + String.join(", ", beyond) + "）");
            }
            if (!parent.allDepartments() && (node.allDepartments() || !parent.departments().containsAll(node.departments()))) {
                problems.add(name + "：部门范围超出上级 " + parent.username());
            }
            if (!parent.allApplications() && (node.allApplications() || !parent.applications().containsAll(node.applications()))) {
                problems.add(name + "：软件范围超出上级 " + parent.username());
            }
        }
        return problems;
    }

    private static Map<Long, AccountNode> indexById(Collection<AccountNode> accounts) {
        var byId = new LinkedHashMap<Long, AccountNode>();
        for (var node : accounts) byId.put(node.id(), node);
        return byId;
    }

    private static Map<Long, List<Long>> indexChildren(Collection<AccountNode> accounts) {
        var children = new HashMap<Long, List<Long>>();
        for (var node : accounts) {
            if (node.parentId() != null) {
                children.computeIfAbsent(node.parentId(), k -> new ArrayList<>()).add(node.id());
            }
        }
        return children;
    }

    private static boolean hasCycle(Map<Long, AccountNode> byId, long startId) {
        var seen = new HashSet<Long>();
        for (Long current = startId; current != null; current = byId.containsKey(current) ? byId.get(current).parentId() : null) {
            if (!seen.add(current)) return true;
        }
        return false;
    }
}
