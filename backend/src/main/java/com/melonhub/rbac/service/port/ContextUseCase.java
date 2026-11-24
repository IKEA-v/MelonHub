package com.melonhub.rbac.service.port;

import com.melonhub.rbac.dto.ContextContracts.CheckResult;
import com.melonhub.rbac.dto.ContextContracts.ContextResult;
import com.melonhub.rbac.dto.ContextContracts.IssueCommand;
import com.melonhub.rbac.dto.Requests;
import java.util.List;
import java.util.Map;

/**
 * 业务系统授权上下文签发、生效权限查询、批量鉴权与撤销用例端口。
 */
public interface ContextUseCase {
    long CONTEXT_SECONDS = 3600;

    Map<String, Object> issue(long app, Requests.Context input, String actor);

    ContextResult issueContext(long app, IssueCommand input, String actor);

    Map<String, Object> effective(long app, String token);

    ContextResult effectiveContext(long app, String token);

    Map<String, Object> check(long app, String token, List<String> requested);

    CheckResult checkPermissions(long app, String token, List<String> requested);

    void revoke(long app, String token, String actor);
}
