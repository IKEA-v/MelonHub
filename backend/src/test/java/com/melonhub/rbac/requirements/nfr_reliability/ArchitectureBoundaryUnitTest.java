package com.melonhub.rbac.requirements.nfr_reliability;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 架构边界自动化守护测试：
 * 1) controller / security / DemoData 只能依赖 service.port，禁止直接依赖 structured 或 ddd 实现；
 * 2) service.structured 必须纯粹，严禁引入 service.ddd 任何类型；
 * 3) service.ddd.domain 必须零框架纯 Java（严禁 Spring/JPA/Jackson/Servlet/DAO/Entity/DTO）；
 * 4) service.ddd.application 禁止直接访问 DAO、Entity、Repository、PermissionCache 或 service.structured。
 */
class ArchitectureBoundaryUnitTest {

    private static final Path MAIN_ROOT = resolveMainJavaRoot();

    private static Path resolveMainJavaRoot() {
        Path direct = Path.of("src/main/java/com/melonhub/rbac");
        if (Files.isDirectory(direct)) return direct;
        return Path.of("backend/src/main/java/com/melonhub/rbac");
    }

    private static List<String> importsOf(Path file) throws IOException {
        var imports = new ArrayList<String>();
        for (String line : Files.readAllLines(file)) {
            String trimmed = line.strip();
            if (trimmed.startsWith("import ")) {
                String target = trimmed.substring(7).replace("static ", "").replace(";", "").strip();
                imports.add(target);
            }
        }
        return imports;
    }

    private static List<Path> javaFilesUnder(String relative) throws IOException {
        Path dir = MAIN_ROOT.resolve(relative);
        assertThat(Files.isDirectory(dir)).as("目录存在: " + dir).isTrue();
        try (Stream<Path> walk = Files.walk(dir)) {
            return walk.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
    }

    @Test
    @DisplayName("ARCH-01 控制器、安全过滤器与 DemoData 仅依赖 service.port，不直接耦合 structured 或 ddd 实现")
    void outerLayersDependOnlyOnServicePorts() throws IOException {
        var violations = new ArrayList<String>();
        var files = new ArrayList<Path>();
        files.addAll(javaFilesUnder("controller"));
        files.addAll(javaFilesUnder("security"));
        files.add(MAIN_ROOT.resolve("config/DemoData.java"));
        for (Path file : files) {
            for (String imp : importsOf(file)) {
                if (imp.startsWith("com.melonhub.rbac.service.structured.")
                        || imp.startsWith("com.melonhub.rbac.service.ddd.")) {
                    violations.add(file.getFileName() + " -> " + imp);
                }
            }
        }
        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("ARCH-02 结构化后端（service.structured）严禁混入任何 DDD 领域或应用对象")
    void structuredBackendContainsZeroDddImports() throws IOException {
        var files = javaFilesUnder("service/structured");
        assertThat(files).hasSizeGreaterThanOrEqualTo(11);
        var violations = new ArrayList<String>();
        for (Path file : files) {
            for (String imp : importsOf(file)) {
                if (imp.startsWith("com.melonhub.rbac.service.ddd.")) {
                    violations.add(file.getFileName() + " -> " + imp);
                }
            }
        }
        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("ARCH-03 DDD 领域层（service.ddd.domain）100% 零框架纯 Java，严禁导入 Spring/JPA/Jackson/DAO/Entity/DTO")
    void dddDomainLayerIsPureJavaWithoutFrameworkDependencies() throws IOException {
        var files = javaFilesUnder("service/ddd/domain");
        assertThat(files).hasSizeGreaterThanOrEqualTo(20);
        var violations = new ArrayList<String>();
        for (Path file : files) {
            for (String imp : importsOf(file)) {
                boolean allowed = imp.startsWith("java.")
                        || imp.startsWith("javax.crypto.")
                        || imp.startsWith("com.melonhub.rbac.service.ddd.domain.");
                if (!allowed) {
                    violations.add(file.getFileName() + " -> " + imp);
                }
            }
        }
        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("ARCH-04 DDD 应用层（service.ddd.application）只能经领域仓储/网关端口访问基础设施，严禁直接依赖 DAO/Entity/Cache/Structured")
    void dddApplicationLayerNeverBypassesDomainPorts() throws IOException {
        var files = javaFilesUnder("service/ddd/application");
        assertThat(files).hasSizeGreaterThanOrEqualTo(10);
        var violations = new ArrayList<String>();
        for (Path file : files) {
            for (String imp : importsOf(file)) {
                boolean forbidden = (imp.startsWith("com.melonhub.rbac.dao.") && !imp.equals("com.melonhub.rbac.dao.Visibility"))
                        || imp.startsWith("com.melonhub.rbac.entity.")
                        || imp.startsWith("com.melonhub.rbac.repository.")
                        || imp.startsWith("com.melonhub.rbac.cache.")
                        || imp.startsWith("com.melonhub.rbac.service.structured.")
                        || imp.startsWith("com.melonhub.rbac.service.ddd.infrastructure.");
                if (forbidden) {
                    violations.add(file.getFileName() + " -> " + imp);
                }
            }
        }
        assertThat(violations).isEmpty();
    }
}
