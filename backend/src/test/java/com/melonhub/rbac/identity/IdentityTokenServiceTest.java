package com.melonhub.rbac.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * 统一身份 JWT 的签发与校验行为测试。
 */
class IdentityTokenServiceTest {

    /**
     * 令牌应包含目标系统、主体和有效期，并能被同一服务校验。
     */
    @Test
    void RIdentityTokenCanBeIssuedAndVerified() {
        IdentityTokenService service = new IdentityTokenService(
                "test-secret-test-secret-test-secret",
                "https://identity.test",
                7200
        );

        String token = service.issue("sso-u1001", List.of("course-project-management"), Instant.now());
        IdentityTokenService.Claims claims = service.verify(token, "course-project-management");

        assertThat(token.split("\\.")).hasSize(3);
        assertThat(claims.subject()).isEqualTo("sso-u1001");
        assertThat(claims.audience()).contains("course-project-management");
        assertThat(claims.expiresAt()).isAfter(Instant.now());
    }

    /**
     * 篡改签名或目标系统不匹配时必须拒绝令牌。
     */
    @Test
    void RIdentityTokenRejectsTamperingAndWrongAudience() {
        IdentityTokenService service = new IdentityTokenService(
                "test-secret-test-secret-test-secret",
                "https://identity.test",
                7200
        );
        String token = service.issue("sso-u1001", List.of("course-project-management"), Instant.now());

        assertThatThrownBy(() -> service.verify(token + "x", "course-project-management"))
                .isInstanceOf(IdentityTokenService.InvalidTokenException.class);
        assertThatThrownBy(() -> service.verify(token, "other-system"))
                .isInstanceOf(IdentityTokenService.InvalidTokenException.class);
    }
}
