package com.github.lisama569.sbomriskservicejava.model;

/**
 * 被拒绝的条目及其可区分原因。
 *
 * @param index  条目在清单中的序号（从 0 开始；文档级问题为 -1）
 * @param reason 拒绝原因
 * @param detail 人类可读的补充说明
 */
public record RejectedItem(int index, RejectReason reason, String detail) {
}
