package com.github.lisama569.sbomriskservicejava.model;

import java.util.List;

/**
 * 单个组件的判定结论。
 *
 * @param component 组件键
 * @param level     CLEAN / UNKNOWN / VULNERABLE / DENIED
 * @param reasons   判定依据（命中的规则编号或 UNKNOWN 原因）
 */
public record ComponentRisk(String component, RiskLevel level, List<String> reasons) {
}
