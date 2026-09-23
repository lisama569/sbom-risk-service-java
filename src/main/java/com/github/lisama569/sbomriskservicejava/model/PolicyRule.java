package com.github.lisama569.sbomriskservicejava.model;

/**
 * 本地维护的策略规则（拒绝名单，按生态+名称匹配，版本范围可选）。
 *
 * @param id      规则编号
 * @param ecosystem 适用生态
 * @param name    组件名
 * @param range   版本范围表达式；null 表示所有版本
 * @param message 命中时的说明
 */
public record PolicyRule(String id, String ecosystem, String name, String range, String message) {
}
