package com.github.lisama569.sbomriskservicejava.version;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses raw version strings into {@link Version} instances.
 *
 * <ul>
 *   <li>{@link #parseSemver}: strict semver.org 2.0.0 grammar, optional leading "v".</li>
 *   <li>{@link #parseLenient}: strict semver, or a loose dotted-numeric form
 *       such as "1.2" / "4.11.3.2024"; anything else is rejected.</li>
 *   <li>{@link #parseBound}: range bounds must be strict semver.</li>
 * </ul>
 */
public final class VersionParser {

    private static final Pattern SEMVER = Pattern.compile(
            "^v?(?<major>0|[1-9]\\d*)\\.(?<minor>0|[1-9]\\d*)\\.(?<patch>0|[1-9]\\d*)"
                    + "(?:-(?<pre>[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?"
                    + "(?:\\+(?<build>[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?$");

    private static final Pattern LOOSE_NUMERIC = Pattern.compile(
            "^v?(?<core>0|[1-9]\\d*(?:\\.(?:0|[1-9]\\d*))*)$");

    private VersionParser() {
    }

    public static ParseResult parseSemver(String raw) {
        if (raw == null || raw.isBlank()) {
            return ParseResult.error("version is blank");
        }
        Matcher m = SEMVER.matcher(raw.trim());
        if (!m.matches()) {
            return ParseResult.error("not a valid semantic version: '" + raw + "'");
        }
        int major = Integer.parseInt(m.group("major"));
        int minor = Integer.parseInt(m.group("minor"));
        int patch = Integer.parseInt(m.group("patch"));
        String pre = m.group("pre");
        List<String> preIds = pre == null ? List.of() : List.of(pre.split("\\."));
        String build = m.group("build");
        return ParseResult.ok(new SemanticVersion(raw.trim(), major, minor, patch, preIds, build));
    }

    public static ParseResult parseLenient(String raw) {
        if (raw == null || raw.isBlank()) {
            return ParseResult.error("version is blank");
        }
        String trimmed = raw.trim();
        ParseResult strict = parseSemver(trimmed);
        if (strict instanceof ParseResult.Ok ok) {
            return ok;
        }
        Matcher m = LOOSE_NUMERIC.matcher(trimmed);
        if (m.matches()) {
            String[] parts = m.group("core").split("\\.");
            int[] core = new int[parts.length];
            for (int i = 0; i < parts.length; i++) {
                core[i] = Integer.parseInt(parts[i]);
            }
            return ParseResult.ok(new GenericVersion(trimmed, core, null));
        }
        return ParseResult.error("not a valid semver or dotted-numeric version: '" + raw + "'");
    }

    public static ParseResult parseBound(String raw) {
        if (raw == null || raw.isBlank()) {
            return ParseResult.error("range bound is blank");
        }
        return parseSemver(raw.trim());
    }
}
