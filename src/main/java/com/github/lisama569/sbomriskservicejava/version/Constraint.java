package com.github.lisama569.sbomriskservicejava.version;

/**
 * A single range constraint.
 *
 * <ul>
 *   <li>COMPARISON: {@code op} applied to strict-semver {@code bound}
 *       ({@code >=1.2.3}, {@code <2.0.0}, {@code !=1.0.0} ...).</li>
 *   <li>EXACT: equality to {@code bound} (e.g. {@code 1.2.3}).</li>
 *   <li>WILDCARD: numeric core prefix ({@code *}, {@code 1.*}, {@code 1.2.*});
 *       {@code wildcardSegments} is the number of fixed segments (0-2).</li>
 * </ul>
 */
public record Constraint(
        ConstraintKind kind,
        ComparisonOp op,
        Version bound,
        int wildcardSegments,
        String raw
) {

    public enum ConstraintKind {
        COMPARISON,
        EXACT,
        WILDCARD
    }

    public static Constraint comparison(ComparisonOp op, Version bound, String raw) {
        return new Constraint(ConstraintKind.COMPARISON, op, bound, 0, raw);
    }

    public static Constraint exact(Version bound, String raw) {
        return new Constraint(ConstraintKind.EXACT, ComparisonOp.EQ, bound, 0, raw);
    }

    public static Constraint wildcard(Version base, int segments, String raw) {
        return new Constraint(ConstraintKind.WILDCARD, null, base, segments, raw);
    }
}
