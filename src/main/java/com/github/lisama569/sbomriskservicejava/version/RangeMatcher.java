package com.github.lisama569.sbomriskservicejava.version;

import com.github.lisama569.sbomriskservicejava.exception.RuleConfigurationException;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses affected-version range expressions and evaluates a component version
 * against them.
 *
 * <p>A range is a disjunction of one or more conjunctions joined by
 * {@code ||}; within one conjunction atoms are separated by spaces or commas
 * and are AND-ed.
 *
 * <ul>
 *   <li>{@code *} — all versions.</li>
 *   <li>{@code 1.*} / {@code 1.2.*} — numeric core prefix wildcard.</li>
 *   <li>{@code 1.2.3} — exact strict semver (including pre-release identity).</li>
 *   <li>{@code >=1.2.3}, {@code >1.2.3}, {@code <=1.2.3}, {@code <1.2.3},
 *       {@code =1.2.3}, {@code !=1.2.3} — comparisons against strict semver.</li>
 *   <li>{@code ^1.2.3} / {@code ~1.2.3} — caret / tilde shorthand, expanded
 *       to comparisons using the caret/tilde semantics below.</li>
 * </ul>
 *
 * <p>Matching is tri-state: {@code true} (in range), {@code false} (provably
 * out of range) and {@code null} (every disjunct has an incomparable bound).
 * Callers must treat {@code null} as UNKNOWN, never as safe.
 */
public final class RangeMatcher {

    private RangeMatcher() {
    }

    public static RangeExpression parse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new RuleConfigurationException("range expression is blank");
        }
        String expr = raw.trim();
        if ("*".equals(expr)) {
            return new RangeExpression(true, List.of(), raw);
        }
        String[] groups = expr.split("\\|\\|");
        List<List<Constraint>> disjunctions = new ArrayList<>();
        for (String group : groups) {
            String[] atoms = group.trim().split("[\\s,]+");
            List<Constraint> conjunction = new ArrayList<>();
            for (String atom : atoms) {
                if (atom.isEmpty()) {
                    continue;
                }
                conjunction.addAll(parseAtom(atom));
            }
            if (conjunction.isEmpty()) {
                throw new RuleConfigurationException("empty disjunction group in range: '" + raw + "'");
            }
            disjunctions.add(List.copyOf(conjunction));
        }
        if (disjunctions.isEmpty()) {
            throw new RuleConfigurationException("empty range expression: '" + raw + "'");
        }
        return new RangeExpression(false, List.copyOf(disjunctions), raw);
    }

    private static List<Constraint> parseAtom(String atom) {
        try {
            char c = atom.charAt(0);
            if (c == '^' || c == '~') {
                return expandShorthand(atom, c);
            }
            if (c == '>' || c == '<' || c == '=' || c == '!') {
                return List.of(parseComparison(atom));
            }
            if (atom.endsWith(".*") || "*".equals(atom)) {
                return List.of(parseWildcard(atom));
            }
            ParseResult bound = VersionParser.parseBound(atom);
            if (bound instanceof ParseResult.Error err) {
                throw new RuleConfigurationException("invalid range atom '" + atom + "': " + err.detail());
            }
            Version v = ((ParseResult.Ok) bound).value();
            return List.of(Constraint.exact(v, atom));
        } catch (RuleConfigurationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new RuleConfigurationException("invalid range atom '" + atom + "': " + e.getMessage());
        }
    }

    private static Constraint parseComparison(String atom) {
        ComparisonOp op;
        String operand;
        if (atom.startsWith(">=")) {
            op = ComparisonOp.GE;
            operand = atom.substring(2);
        } else if (atom.startsWith("<=")) {
            op = ComparisonOp.LE;
            operand = atom.substring(2);
        } else if (atom.startsWith("!=")) {
            op = ComparisonOp.NE;
            operand = atom.substring(2);
        } else if (atom.startsWith(">")) {
            op = ComparisonOp.GT;
            operand = atom.substring(1);
        } else if (atom.startsWith("<")) {
            op = ComparisonOp.LT;
            operand = atom.substring(1);
        } else if (atom.startsWith("=")) {
            op = ComparisonOp.EQ;
            operand = atom.substring(1);
        } else {
            throw new RuleConfigurationException("unrecognized comparison '" + atom + "'");
        }
        ParseResult bound = VersionParser.parseBound(operatorBlank(operand) ? operand : operand);
        bound = VersionParser.parseBound(operand);
        if (bound instanceof ParseResult.Error err) {
            throw new RuleConfigurationException("invalid range bound '" + operand + "': " + err.detail());
        }
        return Constraint.comparison(op, ((ParseResult.Ok) bound).value(), atom);
    }

    private static boolean operatorBlank(String s) {
        return s == null || s.isBlank();
    }

    private static Constraint parseWildcard(String atom) {
        if ("*".equals(atom)) {
            return Constraint.wildcard(null, 0, atom);
        }
        String prefix = atom.substring(0, atom.length() - 2);
        String[] seg = prefix.split("\\.");
        if (seg.length > 2) {
            throw new RuleConfigurationException("wildcard allows at most two fixed segments: '" + atom + "'");
        }
        int[] nums = new int[seg.length];
        for (int i = 0; i < seg.length; i++) {
            if (!seg[i].matches("0|[1-9]\\d*")) {
                throw new RuleConfigurationException("wildcard segment must be a non-negative integer: '" + atom + "'");
            }
            nums[i] = Integer.parseInt(seg[i]);
        }
        int major = seg.length >= 1 ? nums[0] : 0;
        int minor = seg.length == 2 ? nums[1] : 0;
        Version base = new SemanticVersion(prefix + ".*", major, minor, 0, List.of(), null);
        return Constraint.wildcard(base, seg.length, atom);
    }

    /**
     * Expands caret/tilde shorthand into comparison constraints.
     *
     * <p>Caret: {@code ^X.Y.Z} = {@code >=X.Y.Z} and an upper bound that keeps
     * the left-most non-zero core component fixed (semver-compatible updates).
     * Tilde: {@code ~X.Y.Z} = {@code >=X.Y.0,<X.(Y+1).0}.
     */
    private static List<Constraint> expandShorthand(String atom, char kind) {
        String operand = atom.substring(1);
        ParseResult bound = VersionParser.parseBound(operand);
        if (bound instanceof ParseResult.Error err) {
            throw new RuleConfigurationException("invalid range bound '" + operand + "': " + err.detail());
        }
        SemanticVersion v = (SemanticVersion) ((ParseResult.Ok) bound).value();
        Version lower = new SemanticVersion(v.major() + "." + v.minor() + "." + v.patch(),
                v.major(), v.minor(), v.patch(), v.prerelease(), v.buildMetadata());
        SemanticVersion upper;
        if (kind == '^') {
            if (v.major() != 0) {
                upper = new SemanticVersion(atom + ":upper", v.major() + 1, 0, 0, List.of(), null);
            } else if (v.minor() != 0) {
                upper = new SemanticVersion(atom + ":upper", 0, v.minor() + 1, 0, List.of(), null);
            } else {
                upper = new SemanticVersion(atom + ":upper", 0, 0, v.patch() + 1, List.of(), null);
            }
        } else {
            upper = new SemanticVersion(atom + ":upper", v.major(), v.minor() + 1, 0, List.of(), null);
        }
        return List.of(
                Constraint.comparison(ComparisonOp.GE, lower, atom),
                Constraint.comparison(ComparisonOp.LT, upper, atom));
    }

    /**
     * @return true if any disjunct is satisfied, false if every disjunct is
     *         provably false, null if at least one disjunct is undecidable and
     *         none is satisfied
     */
    public static Boolean matches(RangeExpression range, Version version) {
        if (range.matchAll()) {
            return Boolean.TRUE;
        }
        boolean anyIncomparable = false;
        for (List<Constraint> conjunction : range.disjunctions()) {
            Boolean result = matchConjunction(conjunction, version);
            if (result == null) {
                anyIncomparable = true;
            } else if (result) {
                return Boolean.TRUE;
            }
        }
        return anyIncomparable ? null : Boolean.FALSE;
    }

    private static Boolean matchConjunction(List<Constraint> conjunction, Version version) {
        for (Constraint c : conjunction) {
            Boolean ok = matchesConstraint(c, version);
            if (ok == null) {
                return null;
            }
            if (!ok) {
                return Boolean.FALSE;
            }
        }
        return Boolean.TRUE;
    }

    private static Boolean matchesConstraint(Constraint c, Version version) {
        return switch (c.kind()) {
            case EXACT -> matchExact(c.bound(), version);
            case COMPARISON -> matchComparison(c, version);
            case WILDCARD -> matchWildcard(c, version);
        };
    }

    private static Boolean matchExact(Version bound, Version version) {
        ComparisonOutcome cmp = VersionCompare.compare(version, bound);
        return cmp == ComparisonOutcome.INCOMPARABLE ? null : cmp == ComparisonOutcome.EQUAL;
    }

    private static Boolean matchComparison(Constraint c, Version version) {
        ComparisonOutcome cmp = VersionCompare.compare(version, c.bound());
        if (cmp == ComparisonOutcome.INCOMPARABLE) {
            return c.op() == ComparisonOp.NE ? Boolean.TRUE : null;
        }
        return switch (c.op()) {
            case EQ -> cmp == ComparisonOutcome.EQUAL;
            case NE -> cmp != ComparisonOutcome.EQUAL;
            case LT -> cmp == ComparisonOutcome.LOWER;
            case LE -> cmp != ComparisonOutcome.GREATER;
            case GT -> cmp == ComparisonOutcome.GREATER;
            case GE -> cmp != ComparisonOutcome.LOWER;
        };
    }

    private static Boolean matchWildcard(Constraint c, Version version) {
        if (c.wildcardSegments() == 0) {
            return Boolean.TRUE;
        }
        if (version instanceof SemanticVersion sv) {
            if (!sv.prerelease().isEmpty()) {
                // a numeric prefix wildcard covers releases of that line only
                return Boolean.FALSE;
            }
        } else if (version instanceof GenericVersion gv && gv.textualTail() != null) {
            return null;
        }
        int[] core = version.core();
        int[] fixed = c.bound().core();
        for (int i = 0; i < c.wildcardSegments(); i++) {
            int actual = i < core.length ? core[i] : 0;
            if (actual != fixed[i]) {
                return Boolean.FALSE;
            }
        }
        return Boolean.TRUE;
    }
}
