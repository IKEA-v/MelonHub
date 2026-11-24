package com.melonhub.rbac.service.port;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.AdminFunction;
import com.melonhub.rbac.security.AdminPrincipal;
import com.melonhub.rbac.security.ApplicationCaller;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 控制台管理员认证、会话、MFA、API Key 校验与管理员层级账号管理用例端口。
 */
public interface AuthUseCase {
    int PASSWORD_MAX_BYTES = 72;

    static Map<String, Object> view(AdminPrincipal principal) {
        var view = new LinkedHashMap<String, Object>();
        view.put("id", principal.id());
        view.put("username", principal.username());
        view.put("displayName", principal.displayName());
        view.put("role", principal.role());
        view.put("roleName", principal.roleName());
        view.put("functions", principal.functions().stream().map(AdminFunction::code).sorted().toList());
        view.put("root", principal.root());
        view.put("kind", principal.kind());
        view.put("allDepartments", principal.allDepartments());
        view.put("departmentIds", principal.departmentIds().stream().sorted().toList());
        view.put("allApplications", principal.allApplications());
        view.put("applicationIds", principal.applicationIds().stream().sorted().toList());
        return view;
    }

    Map<String, Object> login(Requests.Login input);

    AdminPrincipal admin(String authorization);

    String sessionHash(String authorization);

    void logout(AdminPrincipal principal, String authorization);

    void changePassword(AdminPrincipal principal, String authorization, Requests.PasswordChange input);

    Map<String, Object> setupMfa(AdminPrincipal principal);

    void confirmMfa(AdminPrincipal principal, String code);

    void disableMfa(AdminPrincipal principal, Requests.MfaDisable input);

    void resetMfa(long id, AdminPrincipal actor);

    Map<String, Object> me(AdminPrincipal principal);

    ApplicationCaller application(String key);

    void flushKeyUsage();

    int purgeSessions();

    AdminPrincipal principal(String username);

    List<Map<String, Object>> accounts(AdminPrincipal actor);

    long createAccount(Requests.Account input, AdminPrincipal actor);

    void updateAccount(long id, Requests.AccountUpdate input, AdminPrincipal actor);

    void resetPassword(long id, Requests.PasswordReset input, AdminPrincipal actor);

    void unlock(long id, AdminPrincipal actor);

    void deleteAccount(long id, AdminPrincipal actor);

    void lockTree();

    void requireConsistentWithRole(String role, Set<String> functions);
}
