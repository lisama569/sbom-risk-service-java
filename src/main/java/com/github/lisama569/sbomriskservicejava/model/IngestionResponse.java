package com.github.lisama569.sbomriskservicejava.model;

import java.util.List;

/**
 * 摄入响应：区分整体失败 / 部分成功 / 成功。
 *
 * @param unresolvedCount 本次提交中以“无法判定”持久化的条目数（新写入，非累计）；
 *                        这些条目会在目标报告中以 UNKNOWN 出现并抬高总体结论
 */
public record IngestionResponse(
        String targetId,
        IngestionStatus status,
        int acceptedCount,
        int rejectedCount,
        int duplicateCount,
        int unresolvedCount,
        List<String> components,
        List<RejectedItem> rejected,
        String summary) {
}
