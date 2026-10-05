package com.github.lisama569.sbomriskservicejava.model;

import java.util.Objects;

/**
 * 无法判定的清单条目：条目本身被识别到，但无法得到可靠身份或足够信息
 * （不支持的坐标类型、畸形坐标、缺名称/版本、非法版本等），
 * 因而不能给出 CLEAN/VULNERABLE/DENIED 的确定结论。
 * <p>与已接受的 {@link Component} 分开存储，但同样进入目标报告，
 * 以 {@code UNKNOWN} 结论单独列出并把总体结论至少抬到 {@code UNKNOWN}，
 * 绝不允许“拒绝即消失、总体仍安全”。
 *
 * @param key    稳定标识（生态::名@版本，缺失字段以 ? 占位），用于去重与报告排序
 * @param reason UNKNOWN 判定依据，如 {@code UNKNOWN:unsupported-ecosystem:pypi}
 */
public record UnresolvedComponent(String key, String reason) {

    public UnresolvedComponent {
        Objects.requireNonNull(key, "unresolved key");
        Objects.requireNonNull(reason, "unresolved reason");
    }
}
