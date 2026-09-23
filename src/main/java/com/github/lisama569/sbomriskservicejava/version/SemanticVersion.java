package com.github.lisama569.sbomriskservicejava.version;

import java.util.List;

/**
 * Strict semantic version per semver.org 2.0.0:
 * {@code MAJOR.MINOR.PATCH(-prerelease)?(+build)?}.
 * Instances are created only through {@link VersionParser}.
 */
public final class SemanticVersion implements Version {

    private final String raw;
    private final int major;
    private final int minor;
    private final int patch;
    private final List<String> prerelease;
    private final String buildMetadata;

    SemanticVersion(String raw, int major, int minor, int patch,
                    List<String> prerelease, String buildMetadata) {
        this.raw = raw;
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        this.prerelease = List.copyOf(prerelease);
        this.buildMetadata = buildMetadata;
    }

    public int major() {
        return major;
    }

    public int minor() {
        return minor;
    }

    public int patch() {
        return patch;
    }

    @Override
    public VersionKind kind() {
        return VersionKind.SEMVER;
    }

    @Override
    public String raw() {
        return raw;
    }

    @Override
    public int[] core() {
        return new int[]{major, minor, patch};
    }

    @Override
    public List<String> prerelease() {
        return prerelease;
    }

    @Override
    public String buildMetadata() {
        return buildMetadata;
    }

    @Override
    public String toString() {
        return raw;
    }
}
