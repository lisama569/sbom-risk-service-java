package com.github.lisama569.sbomriskservicejava.model;

import java.util.List;

/**
 * Full outcome of an ingestion request: overall status plus per-entry detail.
 */
public record IngestResult(
        String documentId,
        SbomFormat format,
        IngestStatus status,
        boolean idempotentReplay,
        int totalEntries,
        List<IngestedComponent> accepted,
        List<RejectedEntry> rejected
) {
}
