package com.melonhub.rbac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.security.AdminPrincipal;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.service.AuthService;
import com.melonhub.rbac.service.GovernanceService;
import com.melonhub.rbac.service.RbacService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

/** Administrators graded by department: the account tree and what department-limited administrators can see and change. */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles("test")
@ContextConfiguration(initializers=CloudTestDatabaseGuard.class)
class AdminTreeIntegrationTest {
    private static final String PASSWORD = "Tree-Test-Passw0rd";
    private static final List<String> DEPARTMENT_FUNCTIONS = List.of("org.view", "domain.view", "domain.configure", "domain.assign",
            "governance.view", "request.approve", "review.manage", "audit.view", "user.status");
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired AuthService auth;
    @Autowired RbacService r;
    @Autowired GovernanceService g;
    @Value("${melonhub.admin-username}") String bootstrap;

    String s, top, managerRole, departmentRole;
    long d1, d2, d3, a1, inBoth, inD1, inD2, roleD1, roleD2;

    @BeforeEach void fixture() throws Exception {
        s = Credentials.token().substring(0, 8).toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "x");
        d1 = r.department(new Requests.Department("Tree One", "t1-" + s), null, "test");
        d2 = r.department(new Requests.Department("Tree Two", "t2-" + s), null, "test");
        d3 = r.department(new Requests.Department("Tree Three", "t3-" + s), null, "test");
        a1 = ((Number) r.application(new Requests.Application("Tree App", "ta-" + s, ""), "test").get("id")).longValue();
        inBoth = r.user(new Requests.User("Both " + s, "both-" + s, "", List.of(d1, d2)), null, "test");
        inD1 = r.user(new Requests.User("One " + s, "one-" + s, "", List.of(d1)), null, "test");
        inD2 = r.user(new Requests.User("Two " + s, "two-" + s, "", List.of(d2)), null, "test");
        roleD1 = r.role(new Requests.Role("Reader", "reader", ""), null, d1, a1, "test");
        roleD2 = r.role(new Requests.Role("Reader", "reader", ""), null, d2, a1, "test");
        // A super administrator below the bootstrap account sets up the hierarchy through the API.
        auth.createAccount(new Requests.Account("top-" + s, null, AdminPrincipal.SUPER_ADMIN, PASSWORD, true, null), auth.principal(bootstrap));
        top = login("top-" + s);
        String upper = s.toUpperCase(Locale.ROOT);
        managerRole = "MGR_" + upper;
        departmentRole = "DEP_" + upper;
        var managerFunctions = new ArrayList<>(DEPARTMENT_FUNCTIONS);
        managerFunctions.addAll(List.of("account.manage", "application.manage"));
        as(top, post("/api/admin/admin-roles"), new Requests.AdminRoleCreate(managerRole, "部门经理", "", managerFunctions)).andExpect(status().isOk());
        as(top, post("/api/admin/admin-roles"), new Requests.AdminRoleCreate(departmentRole, "部门管理员", "", DEPARTMENT_FUNCTIONS)).andExpect(status().isOk());
    }

    private String login(String username) throws Exception {
        String body = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("username", username, "password", PASSWORD))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return "Bearer " + mapper.readTree(body).get("token").asText();
    }
    private ResultActions as(String token, MockHttpServletRequestBuilder request, Object body) throws Exception {
        request.header("Authorization", token);
        if (body != null) request.contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(body));
        return mvc.perform(request);
    }
    private JsonNode json(ResultActions result) throws Exception { return mapper.readTree(result.andReturn().getResponse().getContentAsString()); }
    /** An account body; departments null means all departments. */
    private Map<String,Object> account(String name, String role, String kind, List<Long> departments) {
        var body = new HashMap<String,Object>(Map.of("username", name + "-" + s, "role", role, "password", PASSWORD, "kind", kind));
        if (departments == null) body.put("allDepartments", true);
        else { body.put("allDepartments", false); body.put("departmentIds", departments); }
        return body;
    }

    @Test void managersCreateAdministratorsOnlyWithinTheirOwnScope() throws Exception {
        as(top, post("/api/admin/accounts"), account("m1", managerRole, "MANAGER", List.of(d1, d2))).andExpect(status().isOk());
        String manager = login("m1-" + s);
        as(manager, post("/api/admin/accounts"), account("dep1", departmentRole, "DEPARTMENT", List.of(d1))).andExpect(status().isOk());
        // Outside its departments, wider than itself, or a department administrator that could manage accounts.
        as(manager, post("/api/admin/accounts"), account("dep3", departmentRole, "DEPARTMENT", List.of(d3))).andExpect(status().isConflict());
        as(manager, post("/api/admin/accounts"), account("wide", departmentRole, "MANAGER", null)).andExpect(status().isConflict());
        as(manager, post("/api/admin/accounts"), account("depmgr", managerRole, "DEPARTMENT", List.of(d1))).andExpect(status().isConflict());
        as(manager, post("/api/admin/accounts"), account("super", AdminPrincipal.SUPER_ADMIN, "MANAGER", List.of(d1))).andExpect(status().isConflict());

        var listed = new ArrayList<String>();
        json(as(manager, get("/api/admin/accounts"), null).andExpect(status().isOk())).forEach(a -> listed.add(a.get("username").asText()));
        assertThat(listed).containsExactlyInAnyOrder("m1-" + s, "dep1-" + s);
        as(manager, put("/api/admin/accounts/top-" + s), Map.of("role", "ADMIN", "enabled", true)).andExpect(status().isForbidden());
        as(manager, delete("/api/admin/accounts/top-" + s), null).andExpect(status().isForbidden());
        // Its own scope and role are decided above it.
        as(manager, put("/api/admin/accounts/m1-" + s), Map.of("role", managerRole, "enabled", true, "allDepartments", true)).andExpect(status().isBadRequest());
        // Platform-wide functions need an account over all departments, even when the role grants them.
        as(manager, post("/api/admin/applications"), Map.of("name", "x", "code", "x-" + s)).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("该功能只对可管理全部部门的管理员开放"));

        // A department administrator is a leaf: it cannot create accounts at all.
        String department = login("dep1-" + s);
        as(department, post("/api/admin/accounts"), account("leaf", departmentRole, "DEPARTMENT", List.of(d1))).andExpect(status().isForbidden());

        as(top, delete("/api/admin/accounts/m1-" + s), null).andExpect(status().isConflict());
        as(top, delete("/api/admin/accounts/dep1-" + s), null).andExpect(status().isOk());
        as(top, delete("/api/admin/accounts/m1-" + s), null).andExpect(status().isOk());
    }

    @Test void departmentAdministratorsSeeAndChangeOnlyTheirDepartments() throws Exception {
        as(top, post("/api/admin/accounts"), account("dep", departmentRole, "DEPARTMENT", List.of(d1))).andExpect(status().isOk());
        String dep = login("dep-" + s);
        as(dep, get("/api/auth/me"), null).andExpect(jsonPath("$.kind").value("DEPARTMENT"))
                .andExpect(jsonPath("$.allDepartments").value(false)).andExpect(jsonPath("$.departmentIds[0]").value(d1));
        as(dep, get("/api/admin/departments"), null).andExpect(jsonPath("$.length()").value(1)).andExpect(jsonPath("$[0].id").value(d1));

        as(dep, get("/api/admin/roles").param("departmentId", "" + d1).param("applicationId", "" + a1), null).andExpect(status().isOk());
        as(dep, get("/api/admin/roles").param("departmentId", "" + d2).param("applicationId", "" + a1), null).andExpect(status().isForbidden());
        as(dep, post("/api/admin/roles").param("departmentId", "" + d2).param("applicationId", "" + a1), Map.of("name", "W", "code", "w"))
                .andExpect(status().isForbidden());
        as(dep, post("/api/admin/roles").param("departmentId", "" + d1).param("applicationId", "" + a1), Map.of("name", "W", "code", "w"))
                .andExpect(status().isOk());

        // Department staff see their own members and can change the account status within scope.
        as(dep, get("/api/admin/users").param("keyword", s), null).andExpect(jsonPath("$.total").value(2));
        as(dep, get("/api/admin/users").param("departmentId", "" + d2), null).andExpect(status().isForbidden());
        as(dep, post("/api/admin/users"), new Requests.User("New", "new-" + s, "", List.of(d2))).andExpect(status().isForbidden());
        as(dep, post("/api/admin/users"), new Requests.User("New", "new-" + s, "", List.of(d1))).andExpect(status().isForbidden());
        as(dep, put("/api/admin/users/" + inBoth), new Requests.User("Renamed", "both-" + s, "", List.of(d1, d2))).andExpect(status().isForbidden());
        as(dep, put("/api/admin/users/" + inBoth), new Requests.User("Both " + s, "both-" + s, "", List.of(d1))).andExpect(status().isForbidden());
        as(dep, put("/api/admin/users/" + inBoth), new Requests.User("Both " + s, "both-" + s, "", List.of(d2))).andExpect(status().isForbidden());
        as(dep, patch("/api/admin/users/" + inD2 + "/status"), Map.of("enabled", false)).andExpect(status().isForbidden());
        as(dep, patch("/api/admin/users/" + inD1 + "/status"), Map.of("enabled", false)).andExpect(status().isOk());
        as(dep, get("/api/admin/users/" + inD2 + "/access"), null).andExpect(status().isForbidden());

        // Approvals follow the department of the request.
        long own = ((Number) g.submit(a1, new Requests.AccessRequestSubmit("one-" + s, d1, roleD1, "需要", null), "app:" + a1).get("id")).longValue();
        long other = ((Number) g.submit(a1, new Requests.AccessRequestSubmit("two-" + s, d2, roleD2, "需要", null), "app:" + a1).get("id")).longValue();
        as(dep, get("/api/admin/access-requests").param("applicationId", "" + a1), null).andExpect(jsonPath("$.total").value(1));
        as(dep, post("/api/admin/access-requests/" + other + "/approve"), new Requests.RequestApprove(null, "")).andExpect(status().isForbidden());
        as(dep, post("/api/admin/access-requests/" + own + "/approve"), new Requests.RequestApprove(null, "")).andExpect(status().isOk());

        // Reviews over every department and audit records of other departments stay out of reach.
        as(dep, post("/api/admin/reviews"), new Requests.ReviewCreate("All", a1, null, 7)).andExpect(status().isForbidden());
        as(dep, post("/api/admin/reviews"), new Requests.ReviewCreate("Own", a1, d1, 7)).andExpect(status().isOk());
        as(dep, get("/api/admin/audit").param("departmentId", "" + d2), null).andExpect(jsonPath("$.total").value(0));
        as(dep, get("/api/admin/audit").param("departmentId", "" + d1), null).andExpect(jsonPath("$.total").value(org.hamcrest.Matchers.greaterThan(0)));
        as(dep, post("/api/admin/users/import"), new Requests.UserImport(List.of(new Requests.UserImportRow("I", "imp-" + s, "", List.of("t1-" + s)))))
                .andExpect(status().isForbidden());
        as(dep, get("/api/admin/accounts"), null).andExpect(status().isForbidden());
    }

    @Test void roleChangesMustKeepEveryAccountWithinItsParent() throws Exception {
        as(top, post("/api/admin/accounts"), account("m1", managerRole, "MANAGER", List.of(d1, d2))).andExpect(status().isOk());
        as(login("m1-" + s), post("/api/admin/accounts"), account("dep1", departmentRole, "DEPARTMENT", List.of(d1))).andExpect(status().isOk());
        var withAccounts = new ArrayList<>(DEPARTMENT_FUNCTIONS);
        withAccounts.add("account.manage");
        as(top, put("/api/admin/admin-roles/" + departmentRole), new Requests.AdminRoleUpdate("部门管理员", "", withAccounts)).andExpect(status().isConflict());
        var narrower = new ArrayList<>(List.of("org.view", "domain.view", "account.manage"));
        as(top, put("/api/admin/admin-roles/" + managerRole), new Requests.AdminRoleUpdate("部门经理", "", narrower)).andExpect(status().isConflict());
        var wider = new ArrayList<>(DEPARTMENT_FUNCTIONS);
        wider.addAll(List.of("account.manage", "application.manage", "system.view"));
        as(top, put("/api/admin/admin-roles/" + managerRole), new Requests.AdminRoleUpdate("部门经理", "", wider)).andExpect(status().isOk());
    }

    @Test void onlySuperAndPlatformAdministratorsCanChangeUserProfilesAndCredentials() throws Exception {
        String initial = "identity-test-password";
        String replacement = "updated-identity-test-password";
        as(top, post("/api/admin/accounts"), account("owner", "DEPARTMENT_ADMIN", "DEPARTMENT", List.of(d1)))
                .andExpect(status().isOk());
        as(top, post("/api/admin/accounts"), account("editor", departmentRole, "MANAGER", null))
                .andExpect(status().isOk());
        as(top, post("/api/admin/accounts"), account("platform", AdminPrincipal.ADMIN, "MANAGER", null))
                .andExpect(status().isOk());
        String owner = login("owner-" + s);
        String editor = login("editor-" + s);
        String platform = login("platform-" + s);
        var newUser = Map.of("name", "Credential test", "externalId", "credential-" + s,
                "departmentIds", List.of(d1), "identityPassword", initial);
        as(owner, post("/api/admin/users"), newUser).andExpect(status().isForbidden());
        as(editor, post("/api/admin/users"), newUser).andExpect(status().isForbidden());
        as(owner, put("/api/admin/users/" + inD1), new Requests.User("Renamed", "one-" + s, "", List.of(d1)))
                .andExpect(status().isForbidden());
        long id = json(as(platform, post("/api/admin/users"), newUser).andExpect(status().isOk())).get("id").asLong();
        var profile = new Requests.User("Updated", "credential-" + s, "", List.of(d1));
        as(platform, put("/api/admin/users/" + id), profile).andExpect(status().isOk());

        var login = new Requests.IdentityLogin("credential-" + s, initial, List.of("course-project-management"));
        String oldSession = "Bearer " + json(mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(login))).andExpect(status().isOk())).get("accessToken").asText();
        var reset = new Requests.IdentityPassword(replacement);
        as(editor, put("/api/admin/users/" + id + "/identity-password"), reset).andExpect(status().isForbidden());
        as(owner, put("/api/admin/users/" + id + "/identity-password"), reset).andExpect(status().isForbidden());
        as(editor, post("/api/admin/users/import"), new Requests.UserImport(List.of(
                new Requests.UserImportRow("Outside", "two-" + s, "", List.of("t2-" + s)))))
                .andExpect(status().isForbidden());
        as(owner, post("/api/admin/identity/users/import"), new Requests.IdentityUserImport(List.of(
                new Requests.IdentityUserRow("Outside", "two-" + s, replacement, "", List.of(d2)))))
                .andExpect(status().isForbidden());
        as(top, post("/api/admin/admin-roles"), new Requests.AdminRoleCreate("PRIVATE_" + s.toUpperCase(Locale.ROOT),
                "私密操作", "", List.of("user.manage"))).andExpect(status().isForbidden());
        as(top, put("/api/admin/admin-roles/" + departmentRole),
                new Requests.AdminRoleUpdate("私密操作", "", List.of("user.credentials"))).andExpect(status().isForbidden());
        as(platform, put("/api/admin/users/" + id + "/identity-password"), reset).andExpect(status().isOk());
        as(oldSession, get("/auth/me"), null).andExpect(status().isUnauthorized());

        var newLogin = new Requests.IdentityLogin("credential-" + s, replacement, List.of("course-project-management"));
        String newSession = "Bearer " + json(mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(newLogin))).andExpect(status().isOk())).get("accessToken").asText();
        as(owner, patch("/api/admin/users/" + inBoth + "/status"), new Requests.Enabled(false)).andExpect(status().isForbidden());
        as(owner, delete("/api/admin/users/" + id), null).andExpect(status().isForbidden());
        as(owner, patch("/api/admin/users/" + id + "/status"), new Requests.Enabled(false)).andExpect(status().isOk());
        as(owner, patch("/api/admin/users/" + id + "/status"), new Requests.Enabled(true)).andExpect(status().isOk());
        as(newSession, get("/auth/me"), null).andExpect(status().isUnauthorized());
        as(top, put("/api/admin/users/" + id + "/identity-password"), new Requests.IdentityPassword(initial))
                .andExpect(status().isOk());
    }

    @Test void departmentAndSoftwareAdminsUseDifferentScopeAxes() throws Exception {
        long anotherApp = ((Number) r.application(new Requests.Application("Other App", "other-" + s, ""), "test").get("id")).longValue();
        as(top, post("/api/admin/accounts"), account("dept-axis", "DEPARTMENT_ADMIN", "DEPARTMENT", List.of(d1)))
                .andExpect(status().isOk());
        var software = account("app-axis", "APP_ADMIN", "MANAGER", null);
        as(top, post("/api/admin/accounts"), software).andExpect(status().isConflict());
        software.put("allApplications", false);
        software.put("applicationIds", List.of(a1));
        as(top, post("/api/admin/accounts"), software).andExpect(status().isOk());

        String departmentToken = login("dept-axis-" + s);
        as(departmentToken, get("/api/auth/me"), null).andExpect(jsonPath("$.allApplications").value(true))
                .andExpect(jsonPath("$.allDepartments").value(false));
        as(departmentToken, post("/api/admin/roles").param("departmentId", "" + d1).param("applicationId", "" + anotherApp),
                new Requests.Role("Other app role", "other-app", "")).andExpect(status().isOk());
        as(departmentToken, get("/api/admin/roles").param("departmentId", "" + d2).param("applicationId", "" + a1), null)
                .andExpect(status().isForbidden());

        String softwareToken = login("app-axis-" + s);
        as(softwareToken, get("/api/auth/me"), null).andExpect(jsonPath("$.allApplications").value(false))
                .andExpect(jsonPath("$.allDepartments").value(true));
        as(softwareToken, post("/api/admin/roles").param("departmentId", "" + d2).param("applicationId", "" + a1),
                new Requests.Role("Other department role", "other-dept", "")).andExpect(status().isOk());
        as(softwareToken, get("/api/admin/roles").param("departmentId", "" + d1).param("applicationId", "" + anotherApp), null)
                .andExpect(status().isForbidden());
    }

    @Test void aDepartmentThatLimitsAnAdministratorCannotBeDeleted() throws Exception {
        long d4 = r.department(new Requests.Department("Tree Four", "t4-" + s), null, "test");
        as(top, post("/api/admin/accounts"), account("dep4", departmentRole, "DEPARTMENT", List.of(d4))).andExpect(status().isOk());
        as(top, delete("/api/admin/departments/" + d4), null).andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("管理员")));
    }
}
