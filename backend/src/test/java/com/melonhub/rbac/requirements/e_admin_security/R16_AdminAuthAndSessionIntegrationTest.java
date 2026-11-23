package com.melonhub.rbac.requirements.e_admin_security;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.requirements.support.SecurityIntegrationSupport;
import com.melonhub.rbac.security.AdminPrincipal;
import com.melonhub.rbac.security.Credentials;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/** 对应需求：R16（见 doc/requirements.md）。 */
class R16_AdminAuthAndSessionIntegrationTest extends SecurityIntegrationSupport {

    @DisplayName("R16 连续 5 次登录失败锁定账号直至解锁")
    @Test void repeatedFailuresLockAnAccountUntilUnlocked() throws Exception {
        String user = account(AdminPrincipal.ADMIN, null);
        for (int i = 1; i <= 4; i++) attempt(user, "wrong-password-" + i).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("BAD_CREDENTIALS"));
        attempt(user, "wrong-password-5").andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
        attempt(user, PASSWORD).andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCOUNT_LOCKED"));
        auth.unlock(auth.principal(user).id(), ROOT);
        login(user);
        attempt("missing-" + suffix, PASSWORD).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("BAD_CREDENTIALS"));
    }

    @DisplayName("R16 停用管理员账号立即结束其会话并禁止登录")
    @Test void disablingAnAccountEndsItsSessionsAndBlocksLogin() throws Exception {
        String user = account(AdminPrincipal.ADMIN, null);
        String token = login(user);
        mvc.perform(get("/api/auth/me").header("Authorization", token)).andExpect(status().isOk()).andExpect(jsonPath("$.role").value("ADMIN"));
        auth.updateAccount(auth.principal(user).id(), new Requests.AccountUpdate(null, AdminPrincipal.ADMIN, false, null), ROOT);
        mvc.perform(get("/api/auth/me").header("Authorization", token)).andExpect(status().isUnauthorized());
        attempt(user, PASSWORD).andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCOUNT_DISABLED"));
    }

    @DisplayName("R16 管理员会话空闲超时失效且主动退出立即结束会话")
    @Test void idleSessionsExpireAndLogoutEndsTheSession() throws Exception {
        String user = account(AdminPrincipal.ADMIN, null);
        String idle = login(user), active = login(user);
        db.update("UPDATE admin_sessions SET last_seen_at=TIMESTAMPADD(MINUTE,-31,CURRENT_TIMESTAMP) WHERE token_hash=?", Credentials.hash(idle.substring(7)));
        mvc.perform(get("/api/auth/me").header("Authorization", idle)).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/logout").header("Authorization", active)).andExpect(status().isOk());
        mvc.perform(get("/api/auth/me").header("Authorization", active)).andExpect(status().isUnauthorized());
    }

    @DisplayName("R16 修改本人密码保留当前会话并踢掉其他会话")
    @Test void changingOwnPasswordSignsOutOtherSessions() throws Exception {
        String user = account(AdminPrincipal.ADMIN, null);
        String first = login(user), second = login(user);
        mvc.perform(put("/api/auth/password").header("Authorization", first).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("currentPassword", "not-the-password", "newPassword", PASSWORD + "-next")))).andExpect(status().isBadRequest());
        mvc.perform(put("/api/auth/password").header("Authorization", first).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("currentPassword", PASSWORD, "newPassword", PASSWORD + "-next")))).andExpect(status().isOk());
        mvc.perform(get("/api/auth/me").header("Authorization", first)).andExpect(status().isOk());
        mvc.perform(get("/api/auth/me").header("Authorization", second)).andExpect(status().isUnauthorized());
        attempt(user, PASSWORD + "-next").andExpect(status().isOk());
    }

    @DisplayName("R16 凭据变更同步阻止并发登录以旧凭据建立会话")
    @Test void credentialChangesEndSessionsIncludingOneStillBeingCreated() throws Exception {
        String user = account(AdminPrincipal.ADMIN, null);
        String token = login(user);
        var checked = authDao.account(user).orElseThrow();
        auth.resetPassword(auth.principal(user).id(), new Requests.PasswordReset(PASSWORD + "-reset"), ROOT);
        mvc.perform(get("/api/auth/me").header("Authorization", token)).andExpect(status().isUnauthorized());
        // A login that verified the old password just before the reset cannot create its session afterwards.
        assertThat(authDao.createSession(Credentials.hash(Credentials.token()), checked, Instant.now().plusSeconds(600), "127.0.0.1")).isZero();
        // Nor does a session row written with the old credential version authenticate.
        String late = Credentials.token();
        db.update("INSERT INTO admin_sessions(token_hash,account_id,expires_at,source_ip,credential_version) VALUES (?,?,TIMESTAMPADD(HOUR,1,CURRENT_TIMESTAMP),'127.0.0.1',?)",
                Credentials.hash(late), checked.id(), checked.credentialVersion());
        mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + late)).andExpect(status().isUnauthorized());
        String body = attempt(user, PASSWORD + "-reset").andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String fresh = "Bearer " + mapper.readTree(body).get("token").asText();
        var current = authDao.account(user).orElseThrow();
        auth.updateAccount(auth.principal(user).id(), new Requests.AccountUpdate(null, AdminPrincipal.AUDITOR, true, null), ROOT);
        mvc.perform(get("/api/auth/me").header("Authorization", fresh)).andExpect(status().isUnauthorized());
        assertThat(authDao.createSession(Credentials.hash(Credentials.token()), current, Instant.now().plusSeconds(600), "127.0.0.1")).isZero();
    }

    @DisplayName("R16 删除账号后同名重建无法承接旧账号并发登录会话")
    @Test void aLoginCheckedAgainstADeletedAccountCannotOpenASessionForItsNamesake() throws Exception {
        String user = account(AdminPrincipal.ADMIN, null);
        var checked = authDao.account(user).orElseThrow();
        auth.deleteAccount(auth.principal(user).id(), ROOT);
        auth.createAccount(new Requests.Account(user, null, AdminPrincipal.AUDITOR, PASSWORD, true, null), ROOT);
        // A recreated login name has a different ID even when the credential version is the same.
        assertThat(auth.principal(user).id()).isNotEqualTo(checked.id());
        assertThat(authDao.account(user).orElseThrow().credentialVersion()).isEqualTo(checked.credentialVersion());
        assertThat(authDao.createSession(Credentials.hash(Credentials.token()), checked, Instant.now().plusSeconds(600), "127.0.0.1")).isZero();
        attempt(user, PASSWORD).andExpect(status().isOk());
    }

    @DisplayName("R16 含 @ 和 . 的管理员账号名支持正常登录")
    @Test void accountNamesWithAtSignsAndDotsStillSupportLogin() throws Exception {
        String root = login(account(AdminPrincipal.SUPER_ADMIN, null));
        String name = "ops." + suffix + "@corp.example";
        mvc.perform(post("/api/admin/accounts").header("Authorization", root).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("username", name, "role", "ADMIN", "password", PASSWORD)))).andExpect(status().isOk());
        mvc.perform(put("/api/admin/accounts/" + auth.principal(name).id() + "/password").header("Authorization", root).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("password", PASSWORD + "-reset")))).andExpect(status().isOk());
        mvc.perform(post("/api/admin/accounts/" + auth.principal(name).id() + "/unlock").header("Authorization", root)).andExpect(status().isOk());
        attempt(name, PASSWORD + "-reset").andExpect(status().isOk());
        mvc.perform(delete("/api/admin/accounts/" + auth.principal(name).id()).header("Authorization", root)).andExpect(status().isOk());
        // A leading dot would make a path segment the guard refuses, so such a name is never accepted.
        mvc.perform(post("/api/admin/accounts").header("Authorization", root).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("username", ".hidden-" + suffix, "role", "ADMIN", "password", PASSWORD)))).andExpect(status().isBadRequest());
    }

    @DisplayName("R16 超过 72 UTF-8 字节的密码明确拒绝而非静默截断")
    @Test void passwordsBeyondSeventyTwoBytesAreRefusedInsteadOfTruncated() throws Exception {
        String longest = "a".repeat(72);
        String user = "bytes-" + suffix;
        auth.createAccount(new Requests.Account(user, null, AdminPrincipal.ADMIN, longest, true, null), ROOT);
        String body = attempt(user, longest).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String token = "Bearer " + mapper.readTree(body).get("token").asText();
        // BCrypt only reads 72 bytes; a longer password must not sign in as its prefix.
        attempt(user, longest + "b").andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("BAD_CREDENTIALS"));
        String wide = "密".repeat(25);
        mvc.perform(put("/api/auth/password").header("Authorization", token).contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("currentPassword", longest, "newPassword", wide)))).andExpect(status().isBadRequest());
        assertThatThrownBy(() -> auth.createAccount(new Requests.Account("wide-" + suffix, null, AdminPrincipal.ADMIN, wide, true, null), ROOT))
                .isInstanceOf(ApiException.class).hasMessageContaining("72 字节");
    }
}
