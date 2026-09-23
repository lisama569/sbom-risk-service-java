package com.github.lisama569.sbomriskservicejava.model;

import java.util.List;

/**
 * Deterministic risk assessment for one component version.
 */
public record RiskAssessment(
        String componentKey,
        String name,
        String version,
        Verdict verdict,
        String unknownReason,
        List<Finding> findings
) {
}
