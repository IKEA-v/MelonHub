package com.melonhub.rbac.requirements.g_identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.melonhub.rbac.identity.IdentityTokenService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 统一身份 JWT 的签发与校验行为测试。
 * 对应需求：R23（见 doc/requirements.md）。
 */
class R23_IdentityJwtTokenUnitTest {

    /**
     * 令牌应包含目标系统、主体和有效期，并能被同一服务校验。
     */
    @Test
    @DisplayName("R23 统一身份 HS256 JWT 正常签发并校验主体、目标系统与有效期")
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
    @DisplayName("R23 统一身份 JWT 拒绝篡改签名与目标系统不匹配的令牌")
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
