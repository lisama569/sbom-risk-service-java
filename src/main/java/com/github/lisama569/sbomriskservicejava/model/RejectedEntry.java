package com.github.lisama569.sbomriskservicejava.model;

/**
 * A single rejected entry with an index into the submitted entry list
 * and a distinguishable reason.
 */
public record RejectedEntry(
        int index,
        String name,
        String version,
        RejectReason reason,
        String detail
) {
}
