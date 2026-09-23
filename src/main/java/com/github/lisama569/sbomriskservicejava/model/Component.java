package com.github.lisama569.sbomriskservicejava.model;

/**
 * Normalized component model common to all supported SBOM formats.
 *
 * @param key       stable identity key (purl preferred, otherwise ecosystem:name)
 * @param name      component name, never blank
 * @param version   raw version string, never blank
 * @param purl      package URL, may be null
 * @param ecosystem package ecosystem (e.g. npm, maven), may be null
 * @param license   declared license, may be null
 * @param source    originating SBOM format
 */
public record Component(
        String key,
        String name,
        String version,
        String purl,
        String ecosystem,
        String license,
        SbomFormat source
) {
}
