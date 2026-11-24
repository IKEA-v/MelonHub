package com.melonhub.rbac.service.ddd.domain.repository;

import java.util.List;
import java.util.Map;

/** 纯领域分页切片值对象。 */
public record PageSlice(List<Map<String, Object>> items, long total) {}
