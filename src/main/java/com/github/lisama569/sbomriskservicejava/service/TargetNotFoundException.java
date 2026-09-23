package com.github.lisama569.sbomriskservicejava.service;

/** 查询了从未摄入过任何组件的目标。 */
public class TargetNotFoundException extends RuntimeException {
    public TargetNotFoundException(String targetId) {
        super("target not found or has no accepted components: " + targetId);
    }
}
