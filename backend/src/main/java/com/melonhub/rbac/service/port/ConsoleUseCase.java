package com.melonhub.rbac.service.port;

import com.melonhub.rbac.dao.Visibility;
import java.util.Map;

/**
 * 控制台全局搜索与降级容错系统状态看板用例端口。
 */
public interface ConsoleUseCase {
    Map<String, Object> search(String keyword, Visibility visible);

    Map<String, Object> status(Visibility visible);
}
