package com.github.lisama569.sbomriskservicejava.version;

import java.util.List;

/**
 * Parsed affected-version range: a disjunction (OR) of conjunctions (AND) of
 * constraints, or a wildcard matching everything.
 *
 * <p>Example: {@code <0.2.1 || >1.0.0 <1.2.6} is two conjunctions, the
 * second of which ANDs two comparison constraints.
 */
public record RangeExpression(
        boolean matchAll,
        List<List<Constraint>> disjunctions,
        String raw
) {
}
