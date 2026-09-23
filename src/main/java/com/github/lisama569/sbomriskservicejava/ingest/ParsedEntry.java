package com.github.lisama569.sbomriskservicejava.ingest;

/**
 * Raw entry extracted from an SBOM document before normalization.
 * Any field may be null/blank; the {@link Normalizer} turns missing or
 * invalid fields into distinguishable rejections.
 */
public record ParsedEntry(
        int index,
        String name,
        String version,
        String purl,
        String ecosystem,
        String license
) {
}
