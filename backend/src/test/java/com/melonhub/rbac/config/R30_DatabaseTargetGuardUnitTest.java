package com.melonhub.rbac.config;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.env.MockEnvironment;

/**
 * 对应需求：R30（见 doc/requirements.md）。
 * 因需调用包级可见的 {@link CloudDatabaseConfiguration#databaseTargetGuard(org.springframework.core.env.Environment)}，本类保留在 {@code config} 同包下。
 */
class R30_DatabaseTargetGuardUnitTest {
    private MockEnvironment local() {
        var env = new MockEnvironment()
                .withProperty("LOCAL_DB_HOST", "127.0.0.1")
                .withProperty("LOCAL_DB_PORT", "3306")
                .withProperty("spring.datasource.url", "jdbc:mysql://127.0.0.1:3306/melonhub_rbac?sslMode=REQUIRED")
                .withProperty("spring.datasource.username", "root")
                .withProperty("spring.datasource.password", "test-only-placeholder");
        env.setActiveProfiles("local");
        return env;
    }

    private void validate(MockEnvironment env) {
        CloudDatabaseConfiguration.databaseTargetGuard(env).postProcessBeanFactory(new DefaultListableBeanFactory());
    }

    @DisplayName("R30 local 配置使用本机凭据不依赖云端配置")
    @Test void localProfileUsesItsOwnCredentialsWithoutCloudConfiguration() {
        assertThatCode(() -> validate(local())).doesNotThrowAnyException();
    }

    @DisplayName("R30 cloud 配置强制匹配指定数据库端点")
    @Test void cloudProfileStillRequiresItsConfiguredEndpoint() {
        var env = local().withProperty("CLOUD_DB_HOST", "db.example")
                .withProperty("spring.datasource.url", "jdbc:mysql://db.example:3306/melonhub_rbac?sslMode=REQUIRED");
        env.setActiveProfiles("cloud");
        assertThatCode(() -> validate(env)).doesNotThrowAnyException();
        env.setProperty("spring.datasource.url", "jdbc:mysql://127.0.0.1:3306/melonhub_rbac?sslMode=REQUIRED");
        assertThatThrownBy(() -> validate(env)).isInstanceOf(IllegalStateException.class);
    }

    @DisplayName("R30 cloud 配置兼容 Swarm 含下划线服务名（如 lab_mysql）")
    @Test void cloudProfileAcceptsSwarmServiceNamesWithUnderscores() {
        var env = local().withProperty("CLOUD_DB_HOST", "lab_mysql")
                .withProperty("spring.datasource.url", "jdbc:mysql://lab_mysql:3306/melonhub_rbac?sslMode=REQUIRED");
        env.setActiveProfiles("cloud");
        assertThatCode(() -> validate(env)).doesNotThrowAnyException();
    }

    @DisplayName("R30 local 配置禁止指向非回环远程主机")
    @Test void localProfileCannotBeRedirectedToARemoteHost() {
        var env = local().withProperty("LOCAL_DB_HOST", "db.example")
                .withProperty("spring.datasource.url", "jdbc:mysql://db.example:3306/melonhub_rbac?sslMode=REQUIRED");
        assertThatThrownBy(() -> validate(env)).isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @DisplayName("R30 local 配置拦截错库名、错端口或禁用 TLS 参数")
    @ValueSource(strings = {
        "jdbc:mysql://127.0.0.1:3306/other_project?sslMode=REQUIRED",
        "jdbc:mysql://127.0.0.1:3306/melonhub_rbac_test?sslMode=REQUIRED",
        "jdbc:mysql://127.0.0.1:3307/melonhub_rbac?sslMode=REQUIRED",
        "jdbc:mysql://127.0.0.1:3306/melonhub_rbac?sslMode=DISABLED",
        "jdbc:mysql://127.0.0.1:3306/melonhub_rbac?sslMode=REQUIRED&sessionVariables=x",
        "jdbc:mysql://127.0.0.1:3306/melonhub_rbac?sslMode=REQUIRED&sslMode=DISABLED"
    })
    void localProfileRejectsWrongDatabasePortOrUnsafeOptions(String url) {
        assertThatThrownBy(() -> validate(local().withProperty("spring.datasource.url", url))).isInstanceOf(IllegalStateException.class);
    }

    @DisplayName("R30 禁止同时激活冲突的 cloud 与 local Profile")
    @Test void rejectsAmbiguousProfiles() {
        var env = local();
        env.setActiveProfiles("cloud", "local");
        assertThatThrownBy(() -> validate(env)).isInstanceOf(IllegalStateException.class);
    }

    @DisplayName("R30 test 配置强制显式目标并锁定独立测试库 melonhub_rbac_test")
    @Test void testsRequireAnExplicitLocalTargetAndTheIsolatedSchema() {
        var env = local();
        env.setActiveProfiles("test");
        assertThatThrownBy(() -> validate(env)).isInstanceOf(IllegalStateException.class);
        env.setProperty("TEST_DB_TARGET", "local");
        assertThatThrownBy(() -> validate(env)).isInstanceOf(IllegalStateException.class);
        env.setProperty("spring.datasource.url", "jdbc:mysql://127.0.0.1:3306/melonhub_rbac_test?sslMode=REQUIRED");
        assertThatCode(() -> validate(env)).doesNotThrowAnyException();
        env.setProperty("TEST_DB_TARGET", "automatic");
        assertThatThrownBy(() -> validate(env)).isInstanceOf(IllegalStateException.class);
    }
}
