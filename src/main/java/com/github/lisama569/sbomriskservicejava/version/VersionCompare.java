package com.github.lisama569.sbomriskservicejava.version;

/**
 * Deterministic version comparison.
 *
 * <p>Semantic versions follow semver.org 2.0.0 precedence (build metadata
 * ignored; pre-release lower than the corresponding release). Loose numeric
 * versions (e.g. "1.2") are treated as release versions with their core
 * zero-padded, so "1.2" equals "1.2.0". A comparison that would require
 * interpreting pre-release semantics of a loose version, or a textual tail,
 * returns {@link ComparisonOutcome#INCOMPARABLE}.
 */
public final class VersionCompare {

    private VersionCompare() {
    }

    public static ComparisonOutcome compare(Version a, Version b) {
        if (a == null || b == null) {
            return ComparisonOutcome.INCOMPARABLE;
        }
        if (a instanceof GenericVersion ga && b instanceof GenericVersion gb) {
            return compareLoose(ga, gb);
        }
        if (a instanceof SemanticVersion sa && b instanceof SemanticVersion sb) {
            return sign(compareSemver(sa, sb));
        }
        if (a instanceof GenericVersion ga2 && b instanceof SemanticVersion sb2) {
            return crossCompare(ga2, sb2);
        }
        if (a instanceof SemanticVersion sa2 && b instanceof GenericVersion gb2) {
            ComparisonOutcome r = crossCompare(gb2, sa2);
            return r == ComparisonOutcome.INCOMPARABLE ? r : invert(r);
        }
        return ComparisonOutcome.INCOMPARABLE;
    }

    private static ComparisonOutcome compareLoose(GenericVersion a, GenericVersion b) {
        int coreCmp = compareCores(a.core(), b.core());
        if (coreCmp != 0) {
            return sign(coreCmp);
        }
        if (a.textualTail() == null && b.textualTail() == null) {
            return ComparisonOutcome.EQUAL;
        }
        if (a.textualTail() == null || b.textualTail() == null) {
            // numeric release vs. unknown textual suffix: order undefined
            return ComparisonOutcome.INCOMPARABLE;
        }
        int tail = a.textualTail().compareTo(b.textualTail());
        return tail == 0 ? ComparisonOutcome.EQUAL : sign(tail);
    }

    private static ComparisonOutcome crossCompare(GenericVersion loose, SemanticVersion semver) {
        if (loose.textualTail() != null) {
            return ComparisonOutcome.INCOMPARABLE;
        }
        int coreCmp = compareCores(loose.core(), semver.core());
        if (coreCmp != 0) {
            return sign(coreCmp);
        }
        // a purely numeric loose version denotes a release, which outranks
        // any pre-release of the same core
        return semver.prerelease().isEmpty()
                ? ComparisonOutcome.EQUAL
                : ComparisonOutcome.GREATER;
    }

    private static int compareSemver(SemanticVersion a, SemanticVersion b) {
        int core = compareCores(a.core(), b.core());
        if (core != 0) {
            return core;
        }
        if (a.prerelease().isEmpty() && b.prerelease().isEmpty()) {
            return 0;
        }
        if (a.prerelease().isEmpty()) {
            return 1; // release > pre-release
        }
        if (b.prerelease().isEmpty()) {
            return -1;
        }
        return comparePreRelease(a.prerelease(), b.prerelease());
    }

    private static int comparePreRelease(java.util.List<String> a, java.util.List<String> b) {
        int n = Math.min(a.size(), b.size());
        for (int i = 0; i < n; i++) {
            String x = a.get(i);
            String y = b.get(i);
            boolean xNum = x.chars().allMatch(Character::isDigit);
            boolean yNum = y.chars().allMatch(Character::isDigit);
            int cmp;
            if (xNum && yNum) {
                cmp = Long.compare(Long.parseLong(x), Long.parseLong(y));
            } else if (xNum) {
                cmp = -1; // numeric identifiers have lower precedence
            } else if (yNum) {
                cmp = 1;
            } else {
                cmp = x.compareTo(y);
            }
            if (cmp != 0) {
                return cmp;
            }
        }
        return Integer.compare(a.size(), b.size());
    }

    private static int compareCores(int[] a, int[] b) {
        int n = Math.max(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int x = i < a.length ? a[i] : 0;
            int y = i < b.length ? b[i] : 0;
            if (x != y) {
                return Integer.compare(x, y);
            }
        }
        return 0;
    }

    private static ComparisonOutcome sign(int cmp) {
        return cmp < 0 ? ComparisonOutcome.LOWER
                : cmp > 0 ? ComparisonOutcome.GREATER
                : ComparisonOutcome.EQUAL;
    }

    private static ComparisonOutcome invert(ComparisonOutcome o) {
        return switch (o) {
            case LOWER -> ComparisonOutcome.GREATER;
            case GREATER -> ComparisonOutcome.LOWER;
            default -> o;
        };
    }
}
