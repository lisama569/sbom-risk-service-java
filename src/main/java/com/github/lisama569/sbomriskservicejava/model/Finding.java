package com.github.lisama569.sbomriskservicejava.model;

/**
 * One matched rule contributing to a risk assessment.
 */
public record Finding(
        String ruleId,
        String ruleType,
        String severity,
        String matchedRange,
        String basis
) {
}
