package com.melonhub.client;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/** 对应需求：R27（见 doc/requirements.md）。 */
class MelonHubAutoConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(MelonHubAutoConfiguration.class))
            .withPropertyValues("melonhub.client.api-key=test-only");

    @DisplayName("R27 SDK 自动装配在非 Web 应用中不强依赖 Servlet 或 MVC")
    @Test void nonWebApplicationNeedsNeitherMvcNorServlet() {
        runner.withClassLoader(new FilteredClassLoader("org.springframework.web", "jakarta.servlet")).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(MelonHubClient.class).hasSingleBean(MelonHubAuthorizer.class);
            assertThat(context).doesNotHaveBean("melonHubPermissionInterceptor").doesNotHaveBean("melonHubWebMvcConfigurer");
        });
    }

    @DisplayName("R27 SDK 自动装配在 Spring MVC 应用中注册权限拦截器")
    @Test void mvcApplicationStillGetsTheInterceptor() {
        runner.run(context -> assertThat(context).hasNotFailed().hasSingleBean(MelonHubPermissionInterceptor.class)
                .hasSingleBean(MelonHubWebMvcConfigurer.class));
    }

    @DisplayName("R27 SDK 缺少 Servlet API 时跳过 MVC 配置装配")
    @Test void absentServletDoesNotLoadTheMvcConfiguration() {
        runner.withClassLoader(new FilteredClassLoader("jakarta.servlet")).run(context ->
                assertThat(context).hasNotFailed().hasSingleBean(MelonHubClient.class).doesNotHaveBean("melonHubPermissionInterceptor"));
    }
}
