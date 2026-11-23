package com.melonhub.client;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/** 对应需求：R27（见 doc/requirements.md）。 */
class WebhookSignatureVerifierTest {

    private static final String SECRET = "whsec_test";
    private static final String BODY = "{\"type\":\"user.disabled\",\"applicationId\":2,\"data\":{\"externalId\":\"u1\"}}";

    @Test
    @DisplayName("R27 SDK Webhook 签名生成与校验往返通过")
    void roundTripSucceeds() {
        long now = Instant.now().getEpochSecond();
        String header = WebhookSignatureVerifier.sign(SECRET, now, BODY);
        assertThat(WebhookSignatureVerifier.verify(SECRET, header, BODY, 300)).isTrue();
    }

    @Test
    @DisplayName("R27 SDK Webhook 验签拒绝错误密钥")
    void rejectsWrongSecret() {
        String header = WebhookSignatureVerifier.sign("other", Instant.now().getEpochSecond(), BODY);
        assertThat(WebhookSignatureVerifier.verify(SECRET, header, BODY, 300)).isFalse();
    }

    @Test
    @DisplayName("R27 SDK Webhook 验签拒绝超出时间容差的重放请求")
    void rejectsTimestampOutsideTolerance() {
        long old = Instant.now().getEpochSecond() - 600;
        String header = WebhookSignatureVerifier.sign(SECRET, old, BODY);
        assertThat(WebhookSignatureVerifier.verify(SECRET, header, BODY, 300)).isFalse();
    }

    @Test
    @DisplayName("R27 SDK Webhook 验签拒绝被篡改的请求体")
    void rejectsTamperedBody() {
        String header = WebhookSignatureVerifier.sign(SECRET, Instant.now().getEpochSecond(), BODY);
        assertThat(WebhookSignatureVerifier.verify(SECRET, header, BODY.replace("u1", "u2"), 300)).isFalse();
    }

    @Test
    @DisplayName("R27 SDK Webhook 验签拒绝格式非法的签名头")
    void rejectsMalformedHeader() {
        assertThat(WebhookSignatureVerifier.verify(SECRET, null, BODY, 300)).isFalse();
        assertThat(WebhookSignatureVerifier.verify(SECRET, "v1=abc", BODY, 300)).isFalse();
        assertThat(WebhookSignatureVerifier.verify(SECRET, "t=abc,v1=def", BODY, 300)).isFalse();
    }
}
