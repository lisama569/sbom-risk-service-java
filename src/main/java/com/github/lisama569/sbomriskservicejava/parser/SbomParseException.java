package com.github.lisama569.sbomriskservicejava.parser;

/** 清单整体无法解析（畸形 JSON 或不支持的文档形态）。 */
public class SbomParseException extends RuntimeException {
    public SbomParseException(String message) {
        super(message);
    }

    public SbomParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
