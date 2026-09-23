package com.github.lisama569.sbomriskservicejava.model;

/**
 * Risk verdict. UNKNOWN is never treated as safe.
 */
public enum Verdict {
    VULNERABLE,
    POLICY_VIOLATION,
    SAFE,
    UNKNOWN
}
