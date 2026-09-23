package com.github.lisama569.sbomriskservicejava.model;

/** 摄入结果的整体状态：整体失败 / 部分成功 / 全部成功。 */
public enum IngestionStatus {
    FAILED,
    PARTIAL_SUCCESS,
    SUCCESS
}
