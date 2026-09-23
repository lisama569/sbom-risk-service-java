package com.github.lisama569.sbomriskservicejava.ingest;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectedEntry;

/**
 * Outcome of normalizing a single parsed entry.
 */
public sealed interface NormalizationOutcome {

    record Accepted(Component component) implements NormalizationOutcome {
    }

    record Rejected(RejectedEntry entry) implements NormalizationOutcome {
    }
}
