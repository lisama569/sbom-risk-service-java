package com.github.lisama569.sbomriskservicejava.web.dto;

/**
 * 提交请求体。
 *
 * @param targetId 目标编号（幂等域）
 * @param format   可选，cyclonedx / spdx；为空时自动识别
 * @param content  清单原文 JSON
 */
public record SbomSubmissionRequest(String targetId, String format, String content) {
}
