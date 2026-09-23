package com.github.lisama569.sbomriskservicejava.model;

/**
 * Distinguishable rejection reasons for malformed documents or entries.
 */
public enum RejectReason {
    UNSUPPORTED_FORMAT,
    MALFORMED_PAYLOAD,
    MISSING_DOCUMENT,
    MISSING_COMPONENTS,
    INVALID_ENTRY,
    MISSING_NAME,
    MISSING_VERSION,
    INVALID_VERSION,
    INVALID_VERSION_RANGE,
    MISSING_IDENTIFIER,
    DUPLICATE_ENTRY,
    ALREADY_EXISTS,
    INVALID_RULE,
    RULE_NOT_FOUND,
    INTERNAL_ERROR
}
