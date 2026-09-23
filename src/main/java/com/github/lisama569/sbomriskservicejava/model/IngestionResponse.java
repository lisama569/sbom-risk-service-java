package com.github.lisama569.sbomriskservicejava.model;

import java.util.List;

/**
 * 摄入响应：区分整体失败 / 部分成功 / 成功。
 */
public record IngestionResponse(
        String targetId,
        IngestionStatus status,
        int acceptedCount,
        int rejectedCount,
        int duplicateCount,
        List<String> components,
        List<RejectedItem> rejected,
        String summary) {
}
