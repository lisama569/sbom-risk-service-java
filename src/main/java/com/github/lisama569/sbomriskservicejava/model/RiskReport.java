package com.github.lisama569.sbomriskservicejava.model;

import java.util.List;

/**
 * 某目标清单的完整风险判定报告（结论可复现）。
 *
 * @param targetId     目标编号
 * @param overallLevel 汇总等级（取最严重）
 * @param components   每个组件的结论
 * @param rulesVersion 判定时使用的规则版本，保证可复现
 * @param evaluatedAt  判定时间戳（ISO-8601）
 */
public record RiskReport(String targetId, RiskLevel overallLevel,
                         List<ComponentRisk> components, String rulesVersion, String evaluatedAt) {
}
