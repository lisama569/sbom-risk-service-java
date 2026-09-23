package com.github.lisama569.sbomriskservicejava.version;

/** 版本区间表达式非法。 */
public class VersionRangeException extends RuntimeException {
    public VersionRangeException(String message) {
        super(message);
    }
}
