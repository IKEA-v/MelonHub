package com.melonhub.rbac.requirements.e_admin_security;

import static org.assertj.core.api.Assertions.*;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.requirements.support.GovernanceIntegrationSupport;
import com.melonhub.rbac.security.Credentials;
import com.melonhub.rbac.security.Totp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R17（见 doc/requirements.md）。 */
class R17_AdminTotpMfaIntegrationTest extends GovernanceIntegrationSupport {

    @DisplayName("R17 两步验证要求有效口令且禁止同一口令重放")
    @Test void mfaRequiresCurrentCodeAndNeverReplaysOne() {
        var root = auth.principal(bootstrap);
        String username = "mfa-" + Credentials.token().substring(0, 8);
        String password = "mfa-password-123";
        auth.createAccount(new Requests.Account(username, "MFA 用户", "AUDITOR", password, true, null), root);
        var principal = auth.principal(username);
        String beforeEnable = (String) auth.login(new Requests.Login(username, password)).get("token");
        var setup = auth.setupMfa(principal);
        String secret = (String) setup.get("secret");
        assertThat((String) setup.get("uri")).contains("otpauth://totp/MelonHub:" + username);
        assertThatThrownBy(() -> auth.confirmMfa(principal, "000000")).isInstanceOf(ApiException.class);
        auth.confirmMfa(principal, Totp.codeAt(secret, Totp.currentStep()));
        assertThatThrownBy(() -> auth.admin("Bearer " + beforeEnable)).isInstanceOf(ApiException.class);
        // Without a code the login is refused with MFA_REQUIRED.
        assertThatThrownBy(() -> auth.login(new Requests.Login(username, password)))
                .isInstanceOf(ApiException.class).extracting("code").isEqualTo("MFA_REQUIRED");
        String code = Totp.codeAt(secret, Totp.currentStep() + 1);
        String beforeDisable = (String) auth.login(new Requests.Login(username, password, code)).get("token");
        assertThat(auth.admin("Bearer " + beforeDisable).username()).isEqualTo(username);
        // The same code can never sign in twice, even inside its acceptance window.
        assertThatThrownBy(() -> auth.login(new Requests.Login(username, password, code)))
                .isInstanceOf(ApiException.class).extracting("code").isEqualTo("MFA_INVALID");
        // Turning MFA off needs a fresh code too; the one just used to sign in is refused.
        assertThatThrownBy(() -> auth.disableMfa(principal, new Requests.MfaDisable(password, code)))
                .isInstanceOf(ApiException.class).extracting("code").isEqualTo("MFA_INVALID");
        // Stand in for the next 30 s window instead of sleeping until it arrives.
        db.update("UPDATE admin_accounts SET mfa_last_step=mfa_last_step-1 WHERE username=?", username);
        auth.disableMfa(principal, new Requests.MfaDisable(password, code));
        assertThatThrownBy(() -> auth.admin("Bearer " + beforeDisable)).isInstanceOf(ApiException.class);
        String beforeReset = (String) auth.login(new Requests.Login(username, password)).get("token");
        auth.resetMfa(principal.id(), root);
        assertThatThrownBy(() -> auth.admin("Bearer " + beforeReset)).isInstanceOf(ApiException.class);
    }
}
