package com.github.lisama569.sbomriskservicejava.version;

import java.util.ArrayList;
import java.util.List;

/**
 * 语义化版本（major.minor.patch[-prerelease][+build]），可比较。
 * <p>解析规则遵循 <a href="https://semver.org/spec/v2.0.0.html">SemVer 2.0</a>：
 * <ul>
 *   <li>major.minor.patch 三段均为必填非负整数；</li>
 *   <li>预发布标识以 {@code -} 开始、点分段；数字段按数值比较且小于非数字段，带预发布的版本小于正式版；</li>
 *   <li>{@code +} 之后的构建元数据不参与比较。</li>
 * </ul>
 */
public final class SemVer implements Comparable<SemVer> {

    private final int major;
    private final int minor;
    private final int patch;
    /** 预发布段；空列表表示正式版（正式版大于任何预发布版）。 */
    private final List<String> prerelease;
    private final String raw;

    SemVer(int major, int minor, int patch, List<String> prerelease, String raw) {
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        this.prerelease = List.copyOf(prerelease);
        this.raw = raw;
    }

    /** 解析版本字符串，非法时抛 {@link VersionParseException}。 */
    public static SemVer parse(String text) {
        if (text == null) {
            throw new VersionParseException("version is null");
        }
        String raw = text.trim();
        if (raw.isEmpty()) {
            throw new VersionParseException("version is blank");
        }
        // 剥离构建元数据
        String main = raw;
        int plus = main.indexOf('+');
        if (plus >= 0) {
            main = main.substring(0, plus);
        }
        String core;
        List<String> pre = List.of();
        int dash = main.indexOf('-');
        if (dash >= 0) {
            core = main.substring(0, dash);
            String prePart = main.substring(dash + 1);
            if (prePart.isEmpty()) {
                throw new VersionParseException("empty prerelease in version: " + raw);
            }
            pre = parsePrerelease(prePart, raw);
        } else {
            core = main;
        }
        String[] parts = core.split("\\.", -1);
        if (parts.length != 3) {
            throw new VersionParseException(
                    "version must be major.minor.patch, got: " + raw);
        }
        int major = parseNumericId(parts[0], raw, "major");
        int minor = parseNumericId(parts[1], raw, "minor");
        int patch = parseNumericId(parts[2], raw, "patch");
        return new SemVer(major, minor, patch, pre, raw);
    }

    private static List<String> parsePrerelease(String prePart, String raw) {
        String[] ids = prePart.split("\\.", -1);
        List<String> result = new ArrayList<>(ids.length);
        for (String id : ids) {
            if (id.isEmpty()) {
                throw new VersionParseException("empty prerelease identifier in version: " + raw);
            }
            for (int i = 0; i < id.length(); i++) {
                char c = id.charAt(i);
                boolean ok = (c >= '0' && c <= '9')
                        || (c >= 'a' && c <= 'z')
                        || (c >= 'A' && c <= 'Z')
                        || c == '-';
                if (!ok) {
                    throw new VersionParseException(
                            "illegal prerelease identifier '" + id + "' in version: " + raw);
                }
            }
            // 数字型标识符不允许前导 0（0 本身除外）
            if (isDigits(id) && id.length() > 1 && id.charAt(0) == '0') {
                throw new VersionParseException(
                        "numeric prerelease identifier has leading zero: " + id + " in " + raw);
            }
            result.add(id);
        }
        return result;
    }

    private static int parseNumericId(String value, String raw, String segment) {
        if (value.isEmpty() || !isDigits(value)) {
            throw new VersionParseException(
                    segment + " must be a non-negative integer, got version: " + raw);
        }
        if (value.length() > 1 && value.charAt(0) == '0') {
            throw new VersionParseException(
                    segment + " must not have leading zeros in version: " + raw);
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new VersionParseException(segment + " out of range in version: " + raw);
        }
    }

    private static boolean isDigits(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
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

    /** 是否为预发布版本。 */
    public boolean isPrerelease() {
        return !prerelease.isEmpty();
    }

    public String raw() {
        return raw;
    }

    @Override
    public int compareTo(SemVer other) {
        int cmp = Integer.compare(major, other.major);
        if (cmp != 0) {
            return cmp;
        }
        cmp = Integer.compare(minor, other.minor);
        if (cmp != 0) {
            return cmp;
        }
        cmp = Integer.compare(patch, other.patch);
        if (cmp != 0) {
            return cmp;
        }
        return comparePrerelease(prerelease, other.prerelease);
    }

    /** 两个预发布标识列表的比较：空（正式版）大于非空；按标识符逐个比较。 */
    private static int comparePrerelease(List<String> a, List<String> b) {
        if (a.isEmpty() && b.isEmpty()) {
            return 0;
        }
        // 1.0.0（正式）> 1.0.0-alpha
        if (a.isEmpty()) {
            return 1;
        }
        if (b.isEmpty()) {
            return -1;
        }
        int max = Math.min(a.size(), b.size());
        for (int i = 0; i < max; i++) {
            String x = a.get(i);
            String y = b.get(i);
            boolean xNum = isDigits(x);
            boolean yNum = isDigits(y);
            int c;
            if (xNum && yNum) {
                c = Long.compare(Long.parseLong(x), Long.parseLong(y));
            } else if (xNum) {
                // 数字型标识符 < 字符串型
                c = -1;
            } else if (yNum) {
                c = 1;
            } else {
                c = x.compareTo(y);
            }
            if (c != 0) {
                return c;
            }
        }
        return Integer.compare(a.size(), b.size());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SemVer other)) {
            return false;
        }
        return compareTo(other) == 0;
    }

    @Override
    public int hashCode() {
        int result = major;
        result = 31 * result + minor;
        result = 31 * result + patch;
        result = 31 * result + prerelease.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return raw;
    }
}
