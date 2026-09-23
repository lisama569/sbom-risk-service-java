package com.github.lisama569.sbomriskservicejava.model;

/**
 * Overall outcome of an ingestion request.
 */
public enum IngestStatus {
    /** Every entry accepted (or deduped). */
    ACCEPTED,
    /** Some entries accepted, some rejected. */
    PARTIAL,
    /** Document level failure: nothing ingested. */
    FAILED
}
