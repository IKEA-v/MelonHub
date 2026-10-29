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
import com.melonhub.rbac.service.RbacService;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

/** 使用真实过滤器、会话和云测试库验证 HTTP 契约；每个用例的数据随事务回滚。 */
@SpringBootTest
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
@Transactional
@ActiveProfiles("test")
@ContextConfiguration(initializers = CloudTestDatabaseGuard.class)
class ControllerIntegrationTest {
    private static final String PASSWORD = "Controller-Test-Only-2026";
    private static final AdminPrincipal ROOT = new AdminPrincipal("controller-fixture", "fixture",
            AdminPrincipal.SUPER_ADMIN, Set.of());
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired RbacService r;
    @Autowired AuthService auth;
    private final Map<String, String> sessions = new HashMap<>();
    private String suffix, external, key, otherKey;
    private long department, app, otherApp, user, role, permission;

    @BeforeEach void fixture() {
        suffix = Credentials.token().substring(0, 10);
        external = "http-user-" + suffix;
        department = r.department(new Requests.Department("HTTP", "http-" + suffix), null, "test");
        var first = r.application(new Requests.Application("HTTP app", "http-a-" + suffix, ""), "test");
        var second = r.application(new Requests.Application("HTTP other", "http-b-" + suffix, ""), "test");
        app = ((Number) first.get("id")).longValue();
        otherApp = ((Number) second.get("id")).longValue();
        key = (String) first.get("apiKey");
        otherKey = (String) second.get("apiKey");
        user = r.user(new Requests.User("HTTP user", external, "", List.of(department)), null, "test");
        role = r.role(new Requests.Role("Reader", "reader", ""), null, 0, app, "test");
        permission = r.permission(new Requests.Permission("Read", "item:read", "item", "read"), null, 0, app, "test");
        r.rolePermissions(role, 0, app, List.of(permission), "test");
    }

    private String bearer(String type) {
        return sessions.computeIfAbsent(type, value -> {
            String name = "http-" + value + "-" + suffix;
            auth.createAccount(new Requests.Account(name, name, value, PASSWORD, true,
                    value.equals(AdminPrincipal.APP_ADMIN) ? List.of(app) : List.of()), ROOT);
            return "Bearer " + auth.login(new Requests.Login(name, PASSWORD)).get("token");
        });
    }
    private ResultActions as(String type, MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request.header("Authorization", bearer(type)));
    }
    private ResultActions admin(MockHttpServletRequestBuilder request) throws Exception {
        return as(AdminPrincipal.SUPER_ADMIN, request);
    }
    private ResultActions business(MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request.header("X-API-Key", key));
    }
    private MockHttpServletRequestBuilder body(MockHttpServletRequestBuilder request, Object value) throws Exception {
        return request.contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(value));
    }
    private JsonNode ok(ResultActions result) throws Exception {
        return mapper.readTree(result.andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
    private MockHttpServletRequestBuilder scoped(MockHttpServletRequestBuilder request) {
        return request.param("applicationId", Long.toString(app));
    }
    private long submit() throws Exception {
        return ok(business(body(post("/api/v1/access-requests"),
                new Requests.AccessRequestSubmit(external, 0, role, "需要读取", 7)))).path("id").asLong();
    }
    private String context() throws Exception {
        return ok(business(body(post("/api/v1/contexts"), new Requests.Context(external, 0, null))))
                .path("contextToken").asText();
    }

    @Test void approvalsRejectOutOfScopeActorsAndGrantOnlyAfterApproval() throws Exception {
        long id = submit();
        ok(business(get("/api/v1/access-requests").param("externalId", external)));
        assertThat(ok(admin(scoped(get("/api/admin/access-requests")).param("status", "PENDING")))
                .path("total").asInt()).isEqualTo(1);
        var page = ok(as(AdminPrincipal.APP_ADMIN, get("/api/admin/access-requests").param("page", "0").param("size", "999")));
        assertThat(page.path("page").asInt()).isEqualTo(1);
        assertThat(page.path("size").asInt()).isEqualTo(200);
        as(AdminPrincipal.APP_ADMIN, get("/api/admin/access-requests").param("applicationId", Long.toString(otherApp)))
                .andExpect(status().isForbidden());
        long hiddenRole = r.role(new Requests.Role("Hidden", "hidden", ""), null, 0, otherApp, "test");
        long hiddenRequest = ok(mvc.perform(body(post("/api/v1/access-requests"),
                new Requests.AccessRequestSubmit(external, 0, hiddenRole, "其他软件申请", 7))
                .header("X-API-Key", otherKey))).path("id").asLong();
        as(AdminPrincipal.APP_ADMIN, body(post("/api/admin/access-requests/{id}/approve", hiddenRequest), Map.of()))
                .andExpect(status().isForbidden());
        assertThat(ok(mvc.perform(get("/api/v1/access-requests").param("externalId", external)
                .header("X-API-Key", otherKey))).get(0).path("status").asText()).isEqualTo("PENDING");
        as(AdminPrincipal.AUDITOR, body(post("/api/admin/access-requests/{id}/approve", id), Map.of()))
                .andExpect(status().isForbidden());
        assertThat(ok(business(get("/api/v1/users/access").param("externalId", external))).path("roles")).isEmpty();
        var approved = ok(as(AdminPrincipal.APP_ADMIN, body(post("/api/admin/access-requests/{id}/approve", id),
                new Requests.RequestApprove(7, "同意"))));
        assertThat(approved.path("status").asText()).isEqualTo("APPROVED");
        assertThat(approved.path("grantExpiresAt").isTextual()).isTrue();
        assertThat(ok(business(get("/api/v1/users/access").param("externalId", external))).path("permissions"))
                .contains(mapper.valueToTree("item:read"));
        admin(body(post("/api/admin/access-requests/{id}/approve", id), Map.of()))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("CONFLICT"));
    }

    @Test void rejectionAndCancellationDoNotGrantRoles() throws Exception {
        long rejected = submit();
        assertThat(ok(admin(body(post("/api/admin/access-requests/{id}/reject", rejected),
                new Requests.RequestReject("不需要")))).path("status").asText()).isEqualTo("REJECTED");
        long cancelled = submit();
        ok(business(body(post("/api/v1/access-requests/{id}/cancel", cancelled), new Requests.AccessRequestCancel(external))));
        var requests = ok(business(get("/api/v1/access-requests").param("externalId", external)));
        assertThat(requests.findValuesAsText("status")).containsExactlyInAnyOrder("REJECTED", "CANCELLED");
        assertThat(ok(business(get("/api/v1/users/access").param("externalId", external))).path("roles")).isEmpty();
    }

    @Test void reviewDecisionsApplyOnCloseAndRespectApplicationScope() throws Exception {
        r.userRoles(user, 0, app, List.of(role), "test");
        long id = ok(admin(body(post("/api/admin/reviews"), new Requests.ReviewCreate("HTTP review", app, null, 7))))
                .path("id").asLong();
        assertThat(ok(admin(scoped(get("/api/admin/reviews")).param("status", "OPEN"))).size()).isEqualTo(1);
        assertThat(ok(as(AdminPrincipal.APP_ADMIN, get("/api/admin/reviews"))).size()).isEqualTo(1);
        assertThat(ok(admin(get("/api/admin/reviews/{id}", id))).path("status").asText()).isEqualTo("OPEN");
        var items = ok(admin(get("/api/admin/reviews/{id}/items", id).param("page", "0").param("size", "999")));
        assertThat(items.path("total").asInt()).isEqualTo(1);
        assertThat(items.path("page").asInt()).isEqualTo(1);
        assertThat(items.path("size").asInt()).isEqualTo(200);
        long item = items.path("items").get(0).path("id").asLong();
        admin(body(put("/api/admin/reviews/{id}/items/{item}", id, item), Map.of("decision", "INVALID")))
                .andExpect(status().isBadRequest());
        as(AdminPrincipal.AUDITOR, body(put("/api/admin/reviews/{id}/items/{item}", id, item),
                new Requests.ReviewItemDecision("REVOKE", "回收"))).andExpect(status().isForbidden());
        ok(as(AdminPrincipal.APP_ADMIN, body(put("/api/admin/reviews/{id}/items/{item}", id, item),
                new Requests.ReviewItemDecision("REVOKE", "回收"))));
        assertThat(ok(business(get("/api/v1/users/access").param("externalId", external))).path("roles").size()).isEqualTo(1);
        assertThat(ok(admin(post("/api/admin/reviews/{id}/close", id))).path("status").asText()).isEqualTo("CLOSED");
        assertThat(ok(business(get("/api/v1/users/access").param("externalId", external))).path("roles")).isEmpty();
        admin(post("/api/admin/reviews/{id}/close", id)).andExpect(status().isConflict());
        long hidden = ok(admin(body(post("/api/admin/reviews"), new Requests.ReviewCreate("Hidden", otherApp, null, 7))))
                .path("id").asLong();
        as(AdminPrincipal.APP_ADMIN, get("/api/admin/reviews/{id}", hidden)).andExpect(status().isForbidden());
        as(AdminPrincipal.APP_ADMIN, get("/api/admin/reviews").param("applicationId", Long.toString(otherApp)))
                .andExpect(status().isForbidden());
    }

    @Test void webhookCrudAndTestQueueAreScopedAndDoNotExposeSecret() throws Exception {
        var hook = new Requests.Webhook("HTTP hook", "https://example.invalid/hook", null, List.of("user.roles.changed"), true);
        long id = ok(admin(body(post("/api/admin/applications/{id}/webhooks", app), hook))).path("id").asLong();
        var list = ok(admin(get("/api/admin/applications/{id}/webhooks", app)));
        assertThat(list.size()).isEqualTo(1);
        assertThat(list.get(0).has("secret")).isFalse();
        ok(admin(post("/api/admin/webhooks/{id}/test", id)));
        var queued = ok(admin(get("/api/admin/webhooks/{id}/deliveries", id).param("page", "0").param("size", "999")));
        assertThat(queued.path("total").asInt()).isEqualTo(1);
        assertThat(queued.path("items").get(0).path("status").asText()).isEqualTo("PENDING");
        assertThat(queued.path("size").asInt()).isEqualTo(200);
        ok(admin(body(put("/api/admin/webhooks/{id}", id),
                new Requests.Webhook("Disabled", hook.url(), null, hook.events(), false))));
        admin(post("/api/admin/webhooks/{id}/test", id)).andExpect(status().isConflict());
        long hidden = ok(admin(body(post("/api/admin/applications/{id}/webhooks", otherApp), hook))).path("id").asLong();
        as(AdminPrincipal.APP_ADMIN, get("/api/admin/webhooks/{id}/deliveries", hidden)).andExpect(status().isForbidden());
        as(AdminPrincipal.APP_ADMIN, delete("/api/admin/webhooks/{id}", hidden)).andExpect(status().isForbidden());
        ok(admin(delete("/api/admin/webhooks/{id}", id)));
        assertThat(ok(admin(get("/api/admin/applications/{id}/webhooks", app)))).isEmpty();
        admin(get("/api/admin/webhooks/{id}/deliveries", id)).andExpect(status().isNotFound());
    }

    @Test void manifestRoundTripAndUserImportValidateContract() throws Exception {
        var manifest = ok(admin(scoped(get("/api/admin/manifest"))));
        assertThat(manifest.path("version").asInt()).isEqualTo(3);
        assertThat(manifest.path("permissions").size()).isEqualTo(1);
        var body = Map.of("version", 3, "permissions", manifest.path("permissions"), "roles", manifest.path("roles"));
        assertThat(ok(as(AdminPrincipal.APP_ADMIN, body(scoped(post("/api/admin/manifest/import")), body)))
                .path("rolesUpdated").asInt()).isEqualTo(1);
        admin(body(scoped(post("/api/admin/manifest/import")), Map.of("version", 2, "permissions", List.of(), "roles", List.of())))
                .andExpect(status().isBadRequest());
        as(AdminPrincipal.APP_ADMIN, get("/api/admin/manifest").param("applicationId", Long.toString(otherApp)))
                .andExpect(status().isForbidden());
        var users = new Requests.UserImport(List.of(new Requests.UserImportRow("Imported", "import-" + suffix, "", List.of("http-" + suffix))));
        as(AdminPrincipal.APP_ADMIN, body(post("/api/admin/users/import"), users)).andExpect(status().isForbidden());
        assertThat(ok(admin(body(post("/api/admin/users/import"), users))).path("created").asInt()).isEqualTo(1);
        assertThat(ok(admin(body(post("/api/admin/users/import"), users))).path("updated").asInt()).isEqualTo(1);
        admin(body(post("/api/admin/users/import"), Map.of("users", List.of()))).andExpect(status().isBadRequest());
    }

    @Test void reportsFilterVisibleApplicationsAndValidateDays() throws Exception {
        r.userRoles(user, 0, app, List.of(role), 2, null, "test");
        long hiddenRole = r.role(new Requests.Role("Hidden", "hidden", ""), null, 0, otherApp, "test");
        r.userRoles(user, 0, otherApp, List.of(hiddenRole), 2, null, "test");
        var holders = ok(admin(scoped(get("/api/admin/permissions/who")).param("code", "item:read")
                .param("departmentId", Long.toString(department)).param("roleId", Long.toString(role))));
        assertThat(holders.path("total").asInt()).isEqualTo(1);
        assertThat(holders.path("holders").get(0).path("userId").asLong()).isEqualTo(user);
        var visible = ok(as(AdminPrincipal.APP_ADMIN, get("/api/admin/assignments/expiring").param("days", "7")));
        assertThat(visible.size()).isEqualTo(1);
        assertThat(visible.get(0).path("applicationId").asLong()).isEqualTo(app);
        assertThat(ok(admin(scoped(get("/api/admin/assignments/expiring")))).size()).isEqualTo(1);
        for (String days : List.of("0", "366")) admin(get("/api/admin/assignments/expiring").param("days", days))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        as(AdminPrincipal.APP_ADMIN, get("/api/admin/assignments/expiring").param("applicationId", Long.toString(otherApp)))
                .andExpect(status().isForbidden());
        var search = ok(as(AdminPrincipal.APP_ADMIN, get("/api/admin/search").param("q", suffix)));
        assertThat(search.path("applications").size()).isEqualTo(1);
        assertThat(search.path("applications").get(0).path("id").asLong()).isEqualTo(app);
        assertThat(ok(admin(get("/api/admin/system/status"))).path("database").asText()).isEqualTo("UP");
        assertThat(ok(admin(get("/api/admin/audit/verify").param("limit", "0"))).has("ok")).isTrue();
        as(AdminPrincipal.APP_ADMIN, body(put("/api/admin/applications/{id}/rate-limit", app), Map.of("perSecond", 123)))
                .andExpect(status().isForbidden());
        ok(admin(body(put("/api/admin/applications/{id}/rate-limit", app), Map.of("perSecond", 123))));
        assertThat(ok(as(AdminPrincipal.APP_ADMIN, get("/api/admin/applications"))).get(0).path("rateLimit").asInt()).isEqualTo(123);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void businessRoleLifecycleWorksThroughBothRoutesAndRejectsOtherSoftware(boolean legacy) throws Exception {
        String base = legacy ? "/api/v1/departments/" + department : "/api/v1";
        long createdRole = ok(business(body(post(base + "/roles"), new Requests.Role("Writer", "writer", "")))).path("id").asLong();
        long createdPermission = ok(business(body(post(base + "/permissions"), new Requests.Permission("Write", "item:write", "item", "write"))))
                .path("id").asLong();
        ok(business(body(put(base + "/roles/{id}", createdRole), new Requests.Role("Renamed writer", "writer", "updated"))));
        ok(business(body(put(base + "/permissions/{id}", createdPermission), new Requests.Permission("Renamed write", "item:write", "item", "write"))));
        ok(business(body(put(base + "/roles/{id}/permissions", createdRole), new Requests.Ids(List.of(createdPermission)))));
        ok(business(body(put(base + "/users/{id}/roles", user), new Requests.UserRoles(List.of(createdRole)))));
        assertThat(ok(business(get(base + "/users/{id}/roles", user))).path("roleIds"))
                .extracting(JsonNode::asLong).containsExactly(createdRole);
        assertThat(ok(business(get(base + "/roles"))).findValuesAsText("name")).contains("Renamed writer");
        assertThat(ok(business(get(base + "/permissions"))).findValuesAsText("name")).contains("Renamed write");
        mvc.perform(body(put(base + "/roles/{id}", createdRole), new Requests.Role("Intruder", "writer", ""))
                .header("X-API-Key", otherKey)).andExpect(status().isForbidden());
        assertThat(ok(business(get(base + "/roles"))).findValuesAsText("name")).contains("Renamed writer").doesNotContain("Intruder");
        ok(business(body(patch(base + "/roles/{id}/status", createdRole), new Requests.Enabled(false))));
        assertThat(ok(business(get("/api/v1/users/access").param("externalId", external))).path("permissions")).isEmpty();
        ok(business(body(patch(base + "/roles/{id}/status", createdRole), new Requests.Enabled(true))));
        assertThat(ok(business(get("/api/v1/users/access").param("externalId", external))).path("permissions"))
                .containsExactly(mapper.valueToTree("item:write"));
        ok(business(body(put(base + "/users/{id}/roles", user), new Requests.UserRoles(List.of()))));
        assertThat(ok(business(get(base + "/users/{id}/roles", user))).path("roleIds")).isEmpty();
        ok(business(delete(base + "/permissions/{id}", createdPermission)));
        ok(business(delete(base + "/roles/{id}", createdRole)));
        assertThat(ok(business(get(base + "/roles"))).size()).isEqualTo(1);
        assertThat(ok(business(get(base + "/permissions"))).size()).isEqualTo(1);
    }

    @Test void contextChecksRequireHeadersAndRevocationEndsAccess() throws Exception {
        r.userRoles(user, 0, app, List.of(role), "test");
        assertThat(ok(business(get("/api/v1/departments"))).findValuesAsText("code")).contains("http-" + suffix);
        assertThat(ok(business(get("/api/v1/departments/{id}/users", department))).get(0).path("id").asLong()).isEqualTo(user);
        String token = context();
        business(get("/api/v1/contexts/effective")).andExpect(status().isBadRequest());
        assertThat(ok(business(get("/api/v1/contexts/effective").header("X-Context-Token", token))).path("permissions"))
                .containsExactly(mapper.valueToTree("item:read"));
        var check = body(post("/api/v1/contexts/check"), new Requests.Check(List.of("item:read", "item:write")))
                .header("X-Context-Token", token);
        assertThat(ok(business(check)).path("allowed").asBoolean()).isFalse();
        business(body(post("/api/v1/contexts/check"), new Requests.Check(List.of())).header("X-Context-Token", token))
                .andExpect(status().isBadRequest());
        ok(business(delete("/api/v1/contexts").header("X-Context-Token", token)));
        business(get("/api/v1/contexts/effective").header("X-Context-Token", token))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("CONTEXT_INVALID"));
    }

    @Test void adminPlatformCrudAndKeyRotationChangeActualState() throws Exception {
        long dept = ok(admin(body(post("/api/admin/departments"), new Requests.Department("Temp", "temp-" + suffix))))
                .path("id").asLong();
        ok(admin(body(put("/api/admin/departments/{id}", dept), new Requests.Department("Updated", "temp-" + suffix))));
        assertThat(ok(admin(get("/api/admin/departments"))).findValuesAsText("name")).contains("Updated");
        var application = ok(admin(body(post("/api/admin/applications"), new Requests.Application("Temp", "temp-" + suffix, ""))));
        long id = application.path("id").asLong();
        String oldKey = application.path("apiKey").asText();
        ok(admin(body(put("/api/admin/applications/{id}", id), new Requests.Application("Updated app", "temp-" + suffix, "new"))));
        long keyId = ok(admin(body(post("/api/admin/applications/{id}/keys", id), new Requests.ApiKey("Extra", 1))))
                .path("id").asLong();
        assertThat(ok(admin(get("/api/admin/applications/{id}/keys", id))).size()).isEqualTo(2);
        ok(admin(delete("/api/admin/applications/{id}/keys/{key}", id, keyId)));
        String newKey = ok(admin(post("/api/admin/applications/{id}/rotate-key", id))).path("apiKey").asText();
        mvc.perform(get("/api/v1/roles").header("X-API-Key", oldKey)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/roles").header("X-API-Key", newKey)).andExpect(status().isOk());
        ok(admin(body(patch("/api/admin/applications/{id}/status", id), new Requests.Enabled(false))));
        mvc.perform(get("/api/v1/roles").header("X-API-Key", newKey)).andExpect(status().isUnauthorized());
        ok(admin(delete("/api/admin/applications/{id}", id)));
        ok(admin(delete("/api/admin/departments/{id}", dept)));
        assertThat(ok(admin(get("/api/admin/applications"))).findValuesAsText("code")).doesNotContain("temp-" + suffix);
        assertThat(ok(admin(get("/api/admin/departments"))).findValuesAsText("code")).doesNotContain("temp-" + suffix);
    }

    @Test void adminUserLifecyclePaginationAndContextRevocation() throws Exception {
        long id = ok(admin(body(post("/api/admin/users"), new Requests.User("New", "new-" + suffix, "", List.of(department)))))
                .path("id").asLong();
        ok(admin(body(put("/api/admin/users/{id}", id), new Requests.User("Renamed", "new-" + suffix, "", List.of(department)))));
        var list = ok(admin(get("/api/admin/users").param("keyword", "new-" + suffix).param("page", "0").param("size", "999")));
        assertThat(list.path("page").asInt()).isEqualTo(1);
        assertThat(list.path("size").asInt()).isEqualTo(200);
        assertThat(list.path("items").get(0).path("name").asText()).isEqualTo("Renamed");
        assertThat(ok(admin(get("/api/admin/users/export").param("keyword", "new-" + suffix))).path("total").asInt()).isEqualTo(1);
        ok(admin(body(patch("/api/admin/users/{id}/status", id), new Requests.Enabled(false))));
        assertThat(ok(admin(get("/api/admin/users/{id}/access", id))).path("user").path("enabled").asBoolean()).isFalse();
        String token = context();
        assertThat(ok(admin(delete("/api/admin/users/{id}/contexts", user))).path("revoked").asInt()).isEqualTo(1);
        business(get("/api/v1/contexts/effective").header("X-Context-Token", token)).andExpect(status().isUnauthorized());
        ok(admin(delete("/api/admin/users/{id}", id)));
        assertThat(ok(admin(get("/api/admin/users").param("keyword", "new-" + suffix))).path("total").asInt()).isZero();
    }

    @Test void adminAssignmentsMembersAndPermissionEditsAffectAuthorization() throws Exception {
        long id = ok(admin(body(scoped(post("/api/admin/roles")), new Requests.Role("Extra", "extra", "")))).path("id").asLong();
        long perm = ok(admin(body(scoped(post("/api/admin/permissions")), new Requests.Permission("Extra", "item:extra", "item", "extra"))))
                .path("id").asLong();
        ok(admin(body(scoped(put("/api/admin/roles/{id}", id)), new Requests.Role("Updated", "extra", ""))));
        ok(admin(body(scoped(put("/api/admin/permissions/{id}", perm)), new Requests.Permission("Updated", "item:extra", "item", "extra"))));
        ok(admin(body(scoped(put("/api/admin/roles/{id}/permissions", id)), new Requests.Ids(List.of(perm)))));
        ok(admin(body(scoped(put("/api/admin/roles/{id}/members", id)), new Requests.Ids(List.of(user)))));
        assertThat(ok(admin(scoped(get("/api/admin/roles/{id}/members", id)))).get(0).path("id").asLong()).isEqualTo(user);
        assertThat(ok(admin(scoped(get("/api/admin/roles")))).findValuesAsText("name")).contains("Updated");
        assertThat(ok(admin(scoped(get("/api/admin/permissions")))).findValuesAsText("name")).contains("Updated");
        ok(admin(body(scoped(put("/api/admin/users/{id}/roles", user)), new Requests.UserRoles(List.of(role, id)))));
        assertThat(ok(admin(scoped(get("/api/admin/users/{id}/roles", user)))).path("roleIds").size()).isEqualTo(2);
        var assignments = ok(admin(scoped(get("/api/admin/assignments")).param("keyword", external).param("page", "0").param("size", "0")));
        assertThat(assignments.path("total").asInt()).isEqualTo(1);
        assertThat(assignments.path("size").asInt()).isEqualTo(1);
        var simulation = new Requests.Simulation(user, 0, app, null, List.of("item:read", "item:extra"));
        assertThat(ok(admin(body(post("/api/admin/simulate"), simulation))).path("allowed").asBoolean()).isTrue();
        ok(admin(body(scoped(patch("/api/admin/roles/{id}/status", id)), new Requests.Enabled(false))));
        assertThat(ok(admin(body(post("/api/admin/simulate"), simulation))).path("allowed").asBoolean()).isFalse();
        ok(admin(scoped(get("/api/admin/overview"))));
        assertThat(ok(admin(scoped(get("/api/admin/audit")).param("page", "0").param("size", "999"))).path("total").asInt()).isPositive();
        assertThat(ok(admin(scoped(get("/api/admin/audit/export")))).path("total").asInt()).isPositive();
        ok(admin(body(scoped(put("/api/admin/users/{id}/roles", user)), new Requests.UserRoles(List.of()))));
        assertThat(ok(admin(body(scoped(post("/api/admin/assignments/batch")),
                new Requests.BatchUserRoles(List.of(user), List.of(role), null)))).path("grantsAdded").asInt()).isEqualTo(1);
        ok(admin(delete("/api/admin/permissions/{id}", perm).param("applicationId", Long.toString(app))));
        ok(admin(scoped(delete("/api/admin/roles/{id}", id))));
        assertThat(ok(admin(scoped(get("/api/admin/roles")))).size()).isEqualTo(1);
        admin(body(post("/api/admin/domains/copy"), new Requests.DomainCopy(app, department, department)))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test void invalidBodiesAndReadOnlyActorsCannotMutateConfiguration() throws Exception {
        admin(body(scoped(post("/api/admin/roles")), Map.of("name", "", "code", "bad code"))).andExpect(status().isBadRequest());
        admin(body(scoped(put("/api/admin/users/{id}/roles", user)), Map.of())).andExpect(status().isBadRequest());
        admin(scoped(post("/api/admin/roles")).contentType(MediaType.APPLICATION_JSON).content("{"))
                .andExpect(status().isBadRequest());
        as(AdminPrincipal.AUDITOR, body(scoped(put("/api/admin/roles/{id}/permissions", role)), new Requests.Ids(List.of())))
                .andExpect(status().isForbidden());
        as(AdminPrincipal.APP_ADMIN, get("/api/admin/roles").param("applicationId", Long.toString(otherApp)))
                .andExpect(status().isForbidden());
        as(AdminPrincipal.APP_ADMIN, body(post("/api/admin/users"), new Requests.User("Denied", "denied-" + suffix, "", List.of())))
                .andExpect(status().isForbidden());
        assertThat(ok(admin(scoped(get("/api/admin/roles")))).size()).isEqualTo(1);
        assertThat(ok(admin(scoped(get("/api/admin/roles")))).get(0).path("permissionIds"))
                .extracting(JsonNode::asLong).containsExactly(permission);
        assertThat(ok(admin(get("/api/admin/users").param("keyword", "denied-" + suffix))).path("total").asInt()).isZero();
    }
}
