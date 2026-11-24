package com.melonhub.rbac.requirements.f_audit_guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.melonhub.rbac.security.ApiGuard;
import com.melonhub.rbac.security.ApplicationRateLimits;
import com.melonhub.rbac.security.GlobalRateLimiter;
import com.melonhub.rbac.service.port.AuthUseCase;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerMapping;

/** 核对管理菜单请求的完成日志与脱敏边界。 对应需求：R22（见 doc/requirements.md）。 */
@ExtendWith(OutputCaptureExtension.class)
class R22_ApiGuardRequestLogUnitTest {
    /** 记录实际完成的管理请求，日志使用路由模板而非用户输入。 */
    @Test
    @DisplayName("R22 / MH-06 管理菜单请求记录同一请求编号且省略凭据和用户输入")
    void recordsMenuRequestWithoutCredentialsOrUserInput(CapturedOutput output) throws Exception {
        ApiGuard guard = new ApiGuard(mock(AuthUseCase.class), new ObjectMapper(),
                mock(GlobalRateLimiter.class), mock(ApplicationRateLimits.class), 10);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/admin/accounts/42");
        request.addHeader("X-Request-Id", "menu-test-1234");
        request.addHeader("Authorization", "Bearer private-test-token");
        request.setQueryString("keyword=private-search-value");
        MockHttpServletResponse response = new MockHttpServletResponse();

        guard.doFilter(request, response, (incoming, outgoing) -> {
            incoming.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, "/api/admin/accounts/{id}");
            response.setStatus(403);
        });

        assertThat(response.getHeader("X-Request-Id")).isEqualTo("menu-test-1234");
        assertThat(output.getOut())
                .contains("requestId=menu-test-1234 method=GET route=/api/admin/accounts/{id} status=403 durationMs=")
                .doesNotContain("example-user", "private-test-token", "private-search-value");
    }
}
