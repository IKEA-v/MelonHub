package com.melonhub.rbac.controller;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.identity.IdentityService;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 对外提供课程管理系统使用的统一身份认证 API。
 */
@RestController
@RequestMapping("/auth")
public class IdentityController {

    private final IdentityService identityService;

    /**
     * 创建统一身份控制器。
     *
     * @param identityService 统一身份服务
     */
    public IdentityController(IdentityService identityService) {
        this.identityService = identityService;
    }

    /**
     * 登录并返回 JWT。
     *
     * @param body 登录请求
     * @return 登录响应
     */
    @PostMapping("/login")
    public Map<String, Object> login(@Valid @RequestBody Requests.IdentityLogin body) {
        return identityService.login(body.username(), body.password(), body.systems());
    }

    /**
     * 撤销当前 JWT。
     *
     * @param authorization Authorization 请求头
     * @return 空响应
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader(value = "Authorization", required = false) String authorization) {
        identityService.logout(authorization);
        return ResponseEntity.noContent().build();
    }

    /**
     * 查询当前用户、角色和前端权限。
     *
     * @param authorization Authorization 请求头
     * @return 当前用户
     */
    @GetMapping("/me")
    public Map<String, Object> me(@RequestHeader(value = "Authorization", required = false) String authorization) {
        return identityService.currentUser(authorization);
    }

    /**
     * 查询统一身份部门。
     *
     * @param authorization Authorization 请求头
     * @param keyword 部门关键字
     * @param parentId 父部门
     * @param page 页码
     * @param pageSize 页大小
     * @return 部门分页结果
     */
    @GetMapping("/departments")
    public Map<String, Object> departments(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) Long parentId,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int pageSize
    ) {
        return identityService.departments(authorization, keyword, parentId, normalizePage(page), normalizePageSize(pageSize));
    }

    /**
     * 查询部门用户。
     *
     * @param authorization Authorization 请求头
     * @param departmentId 部门主键
     * @param keyword 用户关键字
     * @param page 页码
     * @param pageSize 页大小
     * @return 部门用户分页结果
     */
    @GetMapping("/departments/{departmentId}/users")
    public Map<String, Object> departmentUsers(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable long departmentId,
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int pageSize
    ) {
        return identityService.departmentUsers(authorization, departmentId, keyword, normalizePage(page), normalizePageSize(pageSize));
    }

    /**
     * 查询前端菜单或按钮权限。
     *
     * @param authorization Authorization 请求头
     * @param permission 权限编码
     * @return 是否允许
     */
    @GetMapping("/permissions/{permission}")
    public Map<String, Object> permission(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable String permission
    ) {
        return identityService.checkPermission(authorization, permission);
    }

    /**
     * 查询课程系统 API 全局权限。
     *
     * @param authorization Authorization 请求头
     * @param operationId OpenAPI operationId
     * @return 是否允许
     */
    @GetMapping("/api-permissions/{operationId}")
    public Map<String, Object> apiPermission(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable String operationId
    ) {
        return identityService.checkApiPermission(authorization, operationId);
    }

    /**
     * 按统一身份用户标识查询用户资料。
     *
     * @param authorization Authorization 请求头
     * @param userId 外部用户标识
     * @return 用户资料
     */
    @GetMapping("/users/{userId}")
    public Map<String, Object> user(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable String userId
    ) {
        return identityService.lookupUser(authorization, userId);
    }

    private static int normalizePage(int page) {
        return Math.max(1, page);
    }

    private static int normalizePageSize(int pageSize) {
        return Math.min(100, Math.max(1, pageSize));
    }
}
