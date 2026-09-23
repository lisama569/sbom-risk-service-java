package com.github.lisama569.sbomriskservicejava.version;

import java.util.ArrayList;
import java.util.List;

/**
 * Loose dotted-numeric version that does not satisfy the strict semver grammar
 * (for example "1.2", "4.11.3.2024"). Such versions carry no pre-release
 * semantics; a textual suffix is retained as a non-numeric trailing token.
 *
 * <p>Ordering against another loose version with numeric cores is decidable;
 * ordering against a range bound that would require interpreting the trailing
 * token (or vice versa) yields {@link ComparisonOutcome#INCOMPARABLE}, which
 * the rule engine maps to an UNKNOWN verdict rather than to safe.
 */
public final class GenericVersion implements Version {

    private final String raw;
    private final int[] numericCore;
    private final String textualTail;

    GenericVersion(String raw, int[] numericCore, String textualTail) {
        this.raw = raw;
        this.numericCore = numericCore.clone();
        this.textualTail = textualTail;
    }

    /** Non-numeric trailing token, or null when the whole version is numeric. */
    public String textualTail() {
        return textualTail;
    }

    @Override
    public VersionKind kind() {
        return VersionKind.LOOSE;
    }

    @Override
    public String raw() {
        return raw;
    }

    @Override
    public int[] core() {
        return numericCore.clone();
    }

    @Override
    public List<String> prerelease() {
        return List.of();
    }

    @Override
    public String buildMetadata() {
        return null;
    }

    @Override
    public String toString() {
        return raw;
    }
}
