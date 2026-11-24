package com.melonhub.rbac.service.port;

import com.melonhub.rbac.dao.Visibility;
import com.melonhub.rbac.dto.Requests;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * 授权治理用例端口：角色申请审批、定期权限复核、到期清理、批量导入、清单同步与反查报表。
 */
public interface GovernanceUseCase {
    int HOLDER_LIMIT = 500;

    Map<String, Object> requests(Long app, Visibility visible, String status, String keyword, int page, int size);

    Map<String, Object> request(long id);

    Map<String, Object> submit(long app, Requests.AccessRequestSubmit body, String actor);

    Map<String, Object> approve(long id, Requests.RequestApprove body, String actor);

    Map<String, Object> reject(long id, Requests.RequestReject body, String actor);

    void cancelOwn(long app, long id, String externalId, String actor);

    List<Map<String, Object>> myRequests(long app, String externalId);

    Map<String, Object> myAccess(long app, String externalId, long dept);

    Map<String, Object> createReview(Requests.ReviewCreate body, String actor);

    Map<String, Object> review(long id);

    List<Map<String, Object>> reviews(Long app, Visibility visible, String status);

    Map<String, Object> reviewItems(long review, String decision, int page, int size);

    void decideReviewItem(long reviewId, long itemId, Requests.ReviewItemDecision body, String actor);

    Map<String, Object> closeReview(long reviewId, String actor);

    int expireAssignments(int limit);

    Map<String, Object> importUsers(Requests.UserImport body, String actor);

    Map<String, Object> exportManifest(long app, Long departmentFilter, Collection<Long> visibleDepartments);

    Map<String, Object> importManifest(long app, Requests.Manifest manifest, String actor, Collection<Long> scope);

    Map<String, Object> permissionHolders(long app, String code, Long department, Collection<Long> visibleDepartments);

    List<Map<String, Object>> expiringAssignments(int days, Visibility visible, Long app);
}
