package com.github.lisama569.sbomriskservicejava.model;

/** 条目被拒绝的可区分原因。 */
public enum RejectReason {
    MALFORMED_DOCUMENT,
    UNRECOGNIZED_FORMAT,
    MISSING_COMPONENT_NAME,
    MISSING_COMPONENT_VERSION,
    MALFORMED_VERSION,
    DUPLICATE_COMPONENT,
    UNSUPPORTED_PURL_TYPE
}
