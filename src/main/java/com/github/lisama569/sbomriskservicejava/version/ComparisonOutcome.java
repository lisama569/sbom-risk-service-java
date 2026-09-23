package com.github.lisama569.sbomriskservicejava.version;

/**
 * Tri-state outcome of a version comparison. INCOMPARABLE means the relative
 * order cannot be determined (e.g. a loose version vs. an ordered range bound).
 */
public enum ComparisonOutcome {
    LOWER,
    EQUAL,
    GREATER,
    INCOMPARABLE
}
