package com.melonhub.rbac.service.ddd.application;

import com.melonhub.rbac.dao.Visibility;
import com.melonhub.rbac.exception.ApiErrors;
import com.melonhub.rbac.service.ddd.domain.value.DomainException;
import com.melonhub.rbac.service.ddd.domain.value.DomainVisibility;
import java.util.function.Supplier;

/**
 * DDD 应用层边界辅助：在应用服务出口将纯领域异常 {@link DomainException} 统一映射为 {@link com.melonhub.rbac.exception.ApiException}，
 * 并将接口层 {@link Visibility} 转换为领域值对象 {@link DomainVisibility}。
 */
final class DddBoundary {
    private DddBoundary() {}

    static <T> T execute(Supplier<T> action) {
        try {
            return action.get();
        } catch (DomainException e) {
            throw ApiErrors.toApiException(e);
        }
    }

    static void run(Runnable action) {
        try {
            action.run();
        } catch (DomainException e) {
            throw ApiErrors.toApiException(e);
        }
    }

    static DomainVisibility toDomainVisibility(Visibility visibility) {
        return visibility == null ? DomainVisibility.ALL : new DomainVisibility(visibility.applications(), visibility.departments());
    }
}
