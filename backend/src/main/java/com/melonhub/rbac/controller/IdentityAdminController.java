package com.melonhub.rbac.controller;

import static com.melonhub.rbac.security.AdminFunction.USER_CREDENTIALS;
import static com.melonhub.rbac.security.AdminFunction.USER_MANAGE;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.security.AdminAccess;
import com.melonhub.rbac.security.RequiresFunction;
import com.melonhub.rbac.service.port.IdentityUseCase;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 统一身份测试用户和联调用户的管理接口。
 */
@RestController
@RequestMapping("/api/admin/identity")
public class IdentityAdminController {

    private final IdentityUseCase identityService;

    /**
     * 创建统一身份管理控制器。
     *
     * @param identityService 统一身份服务
     */
    public IdentityAdminController(IdentityUseCase identityService) {
        this.identityService = identityService;
    }

    /**
     * 批量创建或更新统一身份联调用户。
     *
     * @param body 导入请求
     * @param request 管理员请求
     * @return 每行的用户主键
     */
    @RequiresFunction(USER_CREDENTIALS)
    @PostMapping("/users/import")
    public Map<String, Object> importUsers(
            @Valid @RequestBody Requests.IdentityUserImport body,
            HttpServletRequest request
    ) {
        var principal = AdminAccess.allDepartments(request);
        if (!principal.canUse(USER_MANAGE)) throw ApiException.forbidden("批量导入还需要维护用户功能");
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Requests.IdentityUserRow row : body.users()) {
            Requests.User user = new Requests.User(row.name(), row.username(), row.email(), row.departmentIds());
            long id = identityService.provisionUser(user, row.password(), principal.actor());
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("username", row.username());
            result.put("userId", id);
            result.put("status", "imported");
            rows.add(result);
        }
        return Map.of("total", rows.size(), "items", rows);
    }
}
