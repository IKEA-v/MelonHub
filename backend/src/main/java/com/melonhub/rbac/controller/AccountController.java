package com.melonhub.rbac.controller;

import static com.melonhub.rbac.security.AdminFunction.*;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.security.AdminAccess;
import com.melonhub.rbac.security.RequiresFunction;
import com.melonhub.rbac.service.port.AuthUseCase;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.*;

/** Console operator accounts; requires the account management function. */
@RestController
@RequestMapping("/api/admin/accounts")
public class AccountController {
    private final AuthUseCase auth;
    public AccountController(AuthUseCase auth) { this.auth = auth; }

    private static long accountId(long id) {
        if (id < 1) throw ApiException.bad("管理员 ID 必须为正整数");
        return id;
    }

    @RequiresFunction(ACCOUNT_MANAGE)
    @GetMapping List<Map<String,Object>> list(HttpServletRequest req) { return auth.accounts(AdminAccess.of(req)); }
    @RequiresFunction(ACCOUNT_MANAGE)
    @PostMapping Map<String,Object> create(@Valid @RequestBody Requests.Account body, HttpServletRequest req) {
        long id = auth.createAccount(body, AdminAccess.of(req));
        return Map.of("id", id, "username", body.username());
    }
    @RequiresFunction(ACCOUNT_MANAGE)
    @PutMapping("/{id}") Map<String,Object> update(@PathVariable long id, @Valid @RequestBody Requests.AccountUpdate body, HttpServletRequest req) {
        auth.updateAccount(accountId(id), body, AdminAccess.of(req));
        return Map.of("ok", true);
    }
    @RequiresFunction(ACCOUNT_MANAGE)
    @PutMapping("/{id}/password") Map<String,Object> reset(@PathVariable long id, @Valid @RequestBody Requests.PasswordReset body, HttpServletRequest req) {
        auth.resetPassword(accountId(id), body, AdminAccess.of(req));
        return Map.of("ok", true);
    }
    @RequiresFunction(ACCOUNT_MANAGE)
    @PostMapping("/{id}/mfa/reset") Map<String,Object> resetMfa(@PathVariable long id, HttpServletRequest req) {
        auth.resetMfa(accountId(id), AdminAccess.of(req));
        return Map.of("ok", true);
    }
    @RequiresFunction(ACCOUNT_MANAGE)
    @PostMapping("/{id}/unlock") Map<String,Object> unlock(@PathVariable long id, HttpServletRequest req) {
        auth.unlock(accountId(id), AdminAccess.of(req));
        return Map.of("ok", true);
    }
    @RequiresFunction(ACCOUNT_MANAGE)
    @DeleteMapping("/{id}") Map<String,Object> delete(@PathVariable long id, HttpServletRequest req) {
        auth.deleteAccount(accountId(id), AdminAccess.of(req));
        return Map.of("ok", true);
    }
}
