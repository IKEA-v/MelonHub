package com.melonhub.rbac.requirements.b_rbac_domain;

import static org.assertj.core.api.Assertions.*;

import com.melonhub.rbac.dto.Requests;
import com.melonhub.rbac.exception.ApiException;
import com.melonhub.rbac.requirements.support.GovernanceIntegrationSupport;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 对应需求：R6、R7、R8（见 doc/requirements.md）。 */
class R06_R08_GrantExpiryAndManifestIntegrationTest extends GovernanceIntegrationSupport {

    @DisplayName("R8 权限清单导出导入往返配置一致")
    @Test void manifestExportAndImportRoundTrip() {
        var exported = g.exportManifest(a1, d1, null);
        assertThat((List<?>) exported.get("departments")).hasSize(1);
        var manifest = mapper.convertValue(exported, Requests.Manifest.class);
        db.update("UPDATE roles SET name='改名',description='漂移' WHERE id=?", r1);
        db.update("DELETE FROM role_permissions WHERE role_id=?", r2);
        var result = g.importManifest(a1, manifest, "admin", null);
        assertThat(((Number) result.get("rolesUpdated")).intValue()).isEqualTo(2);
        assertThat(((Number) result.get("permissionsUpdated")).intValue()).isEqualTo(2);
        var roles = r.roles(d1, a1);
        var restored = roles.stream().filter(role -> role.get("id").equals(r1) || ((Number) role.get("id")).longValue() == r1).findFirst().orElseThrow();
        assertThat(restored.get("name")).isEqualTo("Reader");
        var writer = roles.stream().filter(role -> ((Number) role.get("id")).longValue() == r2).findFirst().orElseThrow();
        assertThat((List<?>) writer.get("permissionIds")).hasSize(1);
        // Importing into another department creates the configuration there.
        var second = g.importManifest(a1, manifest, "admin", null);
        var target = new Requests.ManifestDepartment(code2, manifest.departments().get(0).permissions(), manifest.departments().get(0).roles());
        var copied = g.importManifest(a1, new Requests.Manifest(1, List.of(target)), "admin", null);
        assertThat(((Number) copied.get("permissionsCreated")).intValue()).isEqualTo(2);
        assertThat(((Number) copied.get("rolesCreated")).intValue()).isEqualTo(2);
        assertThat(r.roles(d2, a1)).hasSize(2);
        assertThat(second.get("rolesUpdated")).isEqualTo(2);
    }

    @DisplayName("R8 清单导入变更角色状态时发出对应通知")
    @Test void manifestImportAnnouncesRolesItDisablesOrRegrants() {
        long hook = ((Number) webhooks.create(a1, new Requests.Webhook("清单通知", "http://127.0.0.1:1/hook", null, List.of("*"), true), ACTOR)
                .get("id")).longValue();
        var section = mapper.convertValue(g.exportManifest(a1, d1, null), Requests.Manifest.class).departments().get(0);
        var roles = section.roles().stream().map(role -> switch (role.code()) {
            case "reader" -> new Requests.ManifestRole(role.code(), role.name(), role.description(), false, role.permissions());
            case "writer" -> new Requests.ManifestRole(role.code(), role.name(), role.description(), true, List.of("item:read", "item:write"));
            default -> role;
        }).toList();
        var manifest = new Requests.Manifest(1, List.of(new Requests.ManifestDepartment(section.code(), section.permissions(), roles)));
        g.importManifest(a1, manifest, "admin", null);
        var events = db.queryForList("SELECT payload FROM webhook_deliveries WHERE webhook_id=? ORDER BY id", String.class, hook);
        assertThat(events).hasSize(2);
        assertThat(events).anySatisfy(payload -> assertThat(payload).contains("\"role.disabled\"").contains("\"roleId\":" + r1));
        assertThat(events).anySatisfy(payload -> assertThat(payload).contains("\"role.permissions.changed\"").contains("\"roleId\":" + r2));
        // Importing the same manifest again changes nothing, so nothing is announced.
        g.importManifest(a1, manifest, "admin", null);
        assertThat(db.queryForObject("SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id=?", Long.class, hook)).isEqualTo(2);
    }

    @DisplayName("R7 重分配角色保留未涉及角色期限并支持逐角色到期")
    @Test @SuppressWarnings("unchecked") void reassigningKeepsUntouchedExpiriesAndAcceptsPerRoleOnes() {
        r.userRoles(u1, d1, a1, List.of(r1), 7, ACTOR);
        Instant week = expiresAt(u1, r1);
        String grant = grantId(u1, r1);
        assertThat(week).isNotNull();
        // Adding a role without saying anything about expiry leaves the existing grant exactly as it was.
        r.userRoles(u1, d1, a1, List.of(r1, r2), ACTOR);
        assertThat(expiresAt(u1, r1)).isEqualTo(week);
        assertThat(grantId(u1, r1)).isEqualTo(grant);
        assertThat(expiresAt(u1, r2)).isNull();
        var soon = OffsetDateTime.now(ZoneOffset.UTC).plusDays(3).withNano(0);
        r.userRoles(u1, d1, a1, List.of(r1, r2), null, List.of(new Requests.RoleExpiry(r2, soon), new Requests.RoleExpiry(r1, null)), ACTOR);
        assertThat(expiresAt(u1, r2)).isEqualTo(soon.toInstant());
        assertThat(expiresAt(u1, r1)).isNull();
        var members = (List<Map<String, Object>>) r.domainAssignments(d1, a1, null, 1, 50).get("items");
        var mine = members.stream().filter(m -> ((Number) m.get("id")).longValue() == u1).findFirst().orElseThrow();
        assertThat(((Map<Long, Object>) mine.get("roleExpiries")).keySet()).containsExactly(r2);
        // The single-user listing carries the same expiry map, keyed by role id.
        var own = r.assignments(u1, d1, a1);
        assertThat((List<Long>) own.get("roleIds")).containsExactly(r1, r2);
        assertThat(((Map<Long, Object>) own.get("roleExpiries")).keySet()).containsExactly(r2);
        assertThatThrownBy(() -> r.userRoles(u1, d1, a1, List.of(r1), null,
                List.of(new Requests.RoleExpiry(r1, OffsetDateTime.now().minusMinutes(1))), ACTOR)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> r.userRoles(u1, d1, a1, List.of(r1), null, List.of(new Requests.RoleExpiry(r2, soon)), ACTOR))
                .isInstanceOf(ApiException.class);
    }

    @DisplayName("R7 批量追加多角色至多成员并保留既有有效分配")
    @Test void batchAddsSeveralRolesToSeveralMembersAndKeepsExistingGrants() {
        r.userRoles(u1, d1, a1, List.of(r1), 7, ACTOR);
        Instant originalExpiry = expiresAt(u1, r1);
        String originalGrant = grantId(u1, r1);
        var result = r.addUserRoles(d1, a1, new Requests.BatchUserRoles(List.of(u1, u2), List.of(r1, r2), 30), ACTOR);
        assertThat(result).containsEntry("changedUsers", 2).containsEntry("grantsAdded", 3);
        assertThat(expiresAt(u1, r1)).isEqualTo(originalExpiry);
        assertThat(grantId(u1, r1)).isEqualTo(originalGrant);
        assertThat(expiresAt(u2, r1)).isBetween(Instant.now().plus(29, ChronoUnit.DAYS), Instant.now().plus(31, ChronoUnit.DAYS));
        assertThat(r.assignments(u2, d1, a1).get("roleIds")).isEqualTo(List.of(r1, r2));
        assertThat(r.addUserRoles(d1, a1, new Requests.BatchUserRoles(List.of(u1, u2), List.of(r1, r2), null), ACTOR))
                .containsEntry("changedUsers", 0).containsEntry("grantsAdded", 0);
        assertThat(expiresAt(u2, r1)).isNotNull();
    }

    @DisplayName("R7 批量追加拒绝跨部门成员或域外角色")
    @Test void batchCannotAssignAcrossDepartmentsOrRolesOutsideTheDomain() {
        long outsider = r.user(new Requests.User("Outside", external + "-outside", "", List.of(d2)), null, ACTOR);
        long otherRole = r.role(new Requests.Role("Other", "other", ""), null, d2, a1, ACTOR);
        assertThatThrownBy(() -> r.addUserRoles(d1, a1, new Requests.BatchUserRoles(List.of(u2, outsider), List.of(r1), null), ACTOR))
                .isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> r.addUserRoles(d1, a1, new Requests.BatchUserRoles(List.of(u2), List.of(r1, otherRole), null), ACTOR))
                .isInstanceOf(ApiException.class);
        assertThat(r.assignments(u2, d1, a1).get("roleIds")).isEqualTo(List.of());
    }

    @DisplayName("R7 过期表单不能将已清理限时授权复活为永久")
    @Test void staleTimedFormCannotRecreateAPurgedGrantPermanently() {
        var expired = OffsetDateTime.now().minusMinutes(1);
        db.update("DELETE FROM user_roles WHERE user_id=? AND role_id=?", u1, r1);
        assertThatThrownBy(() -> r.userRoles(u1, d1, a1, List.of(r1), null, List.of(new Requests.RoleExpiry(r1, expired)), ACTOR))
                .isInstanceOf(ApiException.class).hasMessageContaining("到期时间");
        assertThat(r.assignments(u1, d1, a1).get("roleIds")).isEqualTo(List.of());
    }

    @DisplayName("R6 角色成员新增记录授予人与授予信息")
    @Test void roleMemberAdditionRecordsWhoGrantedWhichMember() {
        r.roleMembers(r2, d1, a1, List.of(u2), ACTOR);
        assertThat(db.queryForObject("SELECT granted_by FROM user_roles WHERE user_id=? AND role_id=?", String.class, u2, r2)).isEqualTo(ACTOR);
        assertThat(db.queryForList("SELECT detail FROM audit_events WHERE actor=? AND action='ROLE_MEMBERS_UPDATED' AND target=?", String.class, ACTOR, "user:" + u2))
                .anySatisfy(detail -> assertThat(detail).contains("writer"));
    }
}
