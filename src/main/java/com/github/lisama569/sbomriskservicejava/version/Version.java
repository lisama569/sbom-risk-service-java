package com.github.lisama569.sbomriskservicejava.version;

/**
 * A parsed component version. Implementations provide deterministic
 * comparison and a raw form for logging.
 */
public sealed interface Version permits SemanticVersion, GenericVersion {

    VersionKind kind();

    String raw();

    /** Numeric core parts, never empty; shorter cores are zero padded when compared. */
    int[] core();

    /** Pre-release identifiers; empty means release. */
    java.util.List<String> prerelease();

    /** Build metadata (ignored in comparisons). */
    String buildMetadata();
}
