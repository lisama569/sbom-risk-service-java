package com.github.lisama569.sbomriskservicejava.version;

/** 版本号无法解析。 */
public class VersionParseException extends RuntimeException {
    public VersionParseException(String message) {
        super(message);
    }
}
