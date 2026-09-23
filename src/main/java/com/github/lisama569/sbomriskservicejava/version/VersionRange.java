package com.github.lisama569.sbomriskservicejava.version;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * 版本范围。
 * <p>单个表达式内部的多个约束以 <b>AND</b> 连接（可用逗号或空白分隔），
 * {@link #compileAny(List)} 接收的多个表达式之间为 <b>OR</b> 关系。
 * <p>支持的约束语法：
 * <ul>
 *   <li>{@code *} / {@code x}：匹配所有版本；</li>
 *   <li>比较：{@code =}、{@code ==}、{@code >}、{@code >=}、{@code <}、{@code <=}；</li>
 *   <li>{@code ^1.2.3}：兼容范围，锁定第一个非零位（SemVer caret 语义）；</li>
 *   <li>{@code ~1.2.3}：补丁范围 {@code >=1.2.3 <1.3.0}；</li>
 *   <li>通配段：{@code 1.x}、{@code 1.2.*}；</li>
 *   <li>区间：{@code [1.0.0,2.0.0)}，方/圆括号表示闭/开端点。</li>
 * </ul>
 * 所有版本号在构造时解析，非法版本或区间立即抛 {@link VersionRangeException}。
 */
public final class VersionRange {

    private final String expression;
    private final List<Predicate<SemVer>> constraints;

    private VersionRange(String expression, List<Predicate<SemVer>> constraints) {
        this.expression = expression;
        this.constraints = List.copyOf(constraints);
    }

    /** 解析单个范围表达式（AND 连接的约束列表），非法时抛 {@link VersionRangeException}。 */
    public static VersionRange compile(String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            throw new VersionRangeException("range expression is blank");
        }
        String expr = expression.trim();
        List<Predicate<SemVer>> constraints = new ArrayList<>();
        if (expr.startsWith("[") || expr.startsWith("(")) {
            // 整体作为一个区间
            constraints.add(compileInterval(expr));
        } else {
            // 逗号或空白分隔
            String[] tokens = expr.split("[,\\s]+");
            for (String token : tokens) {
                if (token.isEmpty()) {
                    continue;
                }
                constraints.add(compileConstraint(token, expression));
            }
        }
        if (constraints.isEmpty()) {
            throw new VersionRangeException("range has no constraints: " + expression);
        }
        return new VersionRange(expr, constraints);
    }

    /** 解析多个表达式（OR 列表）；null/空列表返回空。 */
    public static List<VersionRange> compileAny(List<String> expressions) {
        if (expressions == null) {
            return List.of();
        }
        List<VersionRange> result = new ArrayList<>(expressions.size());
        for (String e : expressions) {
            result.add(compile(e));
        }
        return result;
    }

    /** 判断版本是否落在该范围内（AND 全部满足）。 */
    public boolean contains(SemVer version) {
        for (Predicate<SemVer> c : constraints) {
            if (!c.test(version)) {
                return false;
            }
        }
        return true;
    }

    public String expression() {
        return expression;
    }

    // ---------- 约束编译 ----------

    private static Predicate<SemVer> compileConstraint(String token, String original) {
        // 通配符：* / x / X
        if (token.equals("*") || token.equalsIgnoreCase("x")) {
            return v -> true;
        }
        // 带通配段：1.x / 1.2.* / 1.x.x
        if (token.contains("*") || token.toLowerCase().contains(".x")) {
            return compileWildcard(token, original);
        }
        String op;
        String verText;
        if (token.startsWith(">=")) {
            op = ">=";
            verText = token.substring(2);
        } else if (token.startsWith("<=")) {
            op = "<=";
            verText = token.substring(2);
        } else if (token.startsWith("==")) {
            op = "=";
            verText = token.substring(2);
        } else if (token.startsWith(">")) {
            op = ">";
            verText = token.substring(1);
        } else if (token.startsWith("<")) {
            op = "<";
            verText = token.substring(1);
        } else if (token.startsWith("=")) {
            op = "=";
            verText = token.substring(1);
        } else if (token.startsWith("^")) {
            return compileCaret(token.substring(1), original);
        } else if (token.startsWith("~")) {
            return compileTilde(token.substring(1), original);
        } else {
            // 裸版本视为精确匹配
            op = "=";
            verText = token;
        }
        SemVer bound = parseBound(verText, original);
        return switch (op) {
            case "=" -> v -> v.compareTo(bound) == 0;
            case ">" -> v -> v.compareTo(bound) > 0;
            case ">=" -> v -> v.compareTo(bound) >= 0;
            case "<" -> v -> v.compareTo(bound) < 0;
            case "<=" -> v -> v.compareTo(bound) <= 0;
            default -> throw new VersionRangeException("unknown operator in: " + original);
        };
    }

    private static Predicate<SemVer> compileWildcard(String token, String original) {
        String[] parts = token.split("\\.", -1);
        if (parts.length > 3) {
            throw new VersionRangeException("too many wildcard segments: " + original);
        }
        Integer[] fixed = new Integer[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i].trim();
            if (p.equals("*") || p.equalsIgnoreCase("x")) {
                fixed[i] = null;
            } else {
                try {
                    fixed[i] = Integer.parseInt(p);
                } catch (NumberFormatException e) {
                    throw new VersionRangeException("bad wildcard segment: " + original);
                }
            }
        }
        // 通配位之后必须全部是通配
        boolean afterWildcard = false;
        for (Integer f : fixed) {
            if (f == null) {
                afterWildcard = true;
            } else if (afterWildcard) {
                throw new VersionRangeException(
                        "wildcard must be the last segment: " + original);
            }
        }
        if (fixed[0] == null) {
            return v -> true;
        }
        if (fixed.length == 1 || fixed[1] == null) {
            int base = fixed[0];
            return v -> v.major() == base;
        }
        if (fixed.length == 2 || fixed[2] == null) {
            int baseMajor = fixed[0];
            int baseMinor = fixed[1];
            return v -> v.major() == baseMajor && v.minor() == baseMinor;
        }
        // 无通配位，精确
        SemVer exact = parseBound(token, original);
        return v -> v.compareTo(exact) == 0;
    }

    private static Predicate<SemVer> compileCaret(String verText, String original) {
        PartialVersion pv = parsePartial(verText, original);
        SemVer lower = pv.toSemVer();
        SemVer upper;
        if (pv.major > 0 || pv.minorMissing()) {
            // ^1.2.3 -> <2.0.0；^1 / ^1.2 同样锁定 major
            upper = new SemVer(pv.major + 1, 0, 0, List.of(), "");
        } else if (pv.minor > 0 || pv.patchMissing()) {
            // ^0.2.3 -> <0.3.0；^0.2 -> 锁定 minor
            upper = new SemVer(0, pv.minor + 1, 0, List.of(), "");
        } else {
            // ^0.0.3 -> <0.0.4
            upper = new SemVer(0, 0, pv.patch + 1, List.of(), "");
        }
        return v -> v.compareTo(lower) >= 0 && v.compareTo(upper) < 0;
    }

    private static Predicate<SemVer> compileTilde(String verText, String original) {
        PartialVersion pv = parsePartial(verText, original);
        SemVer lower = pv.toSemVer();
        SemVer upper;
        if (pv.minorMissing()) {
            // ~1 -> >=1.0.0 <2.0.0
            upper = new SemVer(pv.major + 1, 0, 0, List.of(), "");
        } else {
            // ~1.2 / ~1.2.3 -> <1.3.0
            upper = new SemVer(pv.major, pv.minor + 1, 0, List.of(), "");
        }
        return v -> v.compareTo(lower) >= 0 && v.compareTo(upper) < 0;
    }

    private static Predicate<SemVer> compileInterval(String token) {
        if (token.length() < 5) {
            throw new VersionRangeException("interval too short: " + token);
        }
        char left = token.charAt(0);
        char right = token.charAt(token.length() - 1);
        if (left != '[' && left != '(') {
            throw new VersionRangeException("interval must start with [ or (: " + token);
        }
        if (right != ']' && right != ')') {
            throw new VersionRangeException("interval must end with ] or ): " + token);
        }
        String inner = token.substring(1, token.length() - 1);
        int comma = inner.indexOf(',');
        if (comma < 0) {
            throw new VersionRangeException("interval must contain a comma: " + token);
        }
        SemVer low = parseBound(inner.substring(0, comma).trim(), token);
        SemVer high = parseBound(inner.substring(comma + 1).trim(), token);
        if (low.compareTo(high) >= 0) {
            throw new VersionRangeException("interval lower bound must be below upper: " + token);
        }
        return v -> (left == '[' ? v.compareTo(low) >= 0 : v.compareTo(low) > 0)
                && (right == ']' ? v.compareTo(high) <= 0 : v.compareTo(high) < 0);
    }

    private static SemVer parseBound(String verText, String original) {
        if (verText == null || verText.trim().isEmpty()) {
            throw new VersionRangeException("missing version in range: " + original);
        }
        try {
            return SemVer.parse(verText.trim());
        } catch (VersionParseException e) {
            throw new VersionRangeException(
                    "invalid version '" + verText + "' in range '" + original + "': " + e.getMessage());
        }
    }

    /** 允许 1 / 1.2 / 1.2.3 三种完整度。 */
    private static PartialVersion parsePartial(String verText, String original) {
        if (verText == null || verText.trim().isEmpty()) {
            throw new VersionRangeException("missing version after operator in: " + original);
        }
        String[] parts = verText.trim().split("\\.", -1);
        if (parts.length > 3) {
            throw new VersionRangeException("too many version segments in: " + original);
        }
        int[] vals = new int[3];
        try {
            for (int i = 0; i < parts.length; i++) {
                vals[i] = Integer.parseInt(parts[i].trim());
            }
        } catch (NumberFormatException e) {
            throw new VersionRangeException("invalid partial version '" + verText + "' in: " + original);
        }
        return new PartialVersion(vals[0], vals[1], vals[2], parts.length);
    }

    private record PartialVersion(int major, int minor, int patch, int segments) {
        boolean minorMissing() {
            return segments < 2;
        }

        boolean patchMissing() {
            return segments < 3;
        }

        SemVer toSemVer() {
            return new SemVer(major, minor, patch, List.of(), "");
        }
    }
}
