package com.github.lisama569.sbomriskservicejava.version;

/**
 * Outcome of parsing a version or range string.
 */
public sealed interface ParseResult {

    record Ok(Version value) implements ParseResult {
    }

    record Error(String detail) implements ParseResult {
    }

    static ParseResult ok(Version v) {
        return new Ok(v);
    }

    static ParseResult error(String detail) {
        return new Error(detail);
    }
}
