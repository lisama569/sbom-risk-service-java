package com.github.lisama569.sbomriskservicejava.model;

/**
 * Result entry for a component that was accepted (newly stored or deduped).
 */
public record IngestedComponent(
        String key,
        String name,
        String version,
        boolean duplicate,
        String documentId
) {
}
