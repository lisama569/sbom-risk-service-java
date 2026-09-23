package com.github.lisama569.sbomriskservicejava.version;

/**
 * Classification of a parsed version.
 */
public enum VersionKind {
    /** Strict semantic version, e.g. 1.2.3 / 2.0.0-alpha+build.7. */
    SEMVER,
    /** Loose dotted-numeric version, e.g. 1.2 or 4.11.3. */
    LOOSE
}
