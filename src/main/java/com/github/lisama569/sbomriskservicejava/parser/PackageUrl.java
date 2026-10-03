package com.github.lisama569.sbomriskservicejava.parser;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Package URL（purl）解析：把 {@code pkg:type/namespace/name@version} 形式的包坐标
 * 解析为统一组件身份（生态 + 规范名）。
 * <p>解析结果三态可区分：
 * <ul>
 *   <li>{@link Status#OK}：受支持的坐标类型（maven/npm），给出规范身份；</li>
 *   <li>{@link Status#UNSUPPORTED_TYPE}：结构合法但坐标类型暂不支持，
 *       仅给出通用身份（生态=类型），由判定层归入“无法判定”，不得当普通名字；</li>
 *   <li>{@link Status#MALFORMED}：结构无法解析，给不出任何可靠身份。</li>
 * </ul>
 */
final class PackageUrl {

    enum Status { OK, UNSUPPORTED_TYPE, MALFORMED }

    /**
     * @param status        解析结果分类
     * @param ecosystem     归一化生态（OK/UNSUPPORTED_TYPE 时非空）
     * @param canonicalName 规范组件名（OK/UNSUPPORTED_TYPE 时非空）
     * @param detail        人类可读说明（主要用于 MALFORMED / UNSUPPORTED_TYPE）
     */
    record Result(Status status, String ecosystem, String canonicalName, String detail) {
        boolean ok() {
            return status == Status.OK;
        }
    }

    private PackageUrl() {
    }

    /** 解析 purl；入参为 null/空白时返回 MALFORMED。 */
    static Result parse(String purl) {
        if (purl == null || purl.isBlank()) {
            return malformed("purl is blank");
        }
        String p = purl.trim();
        if (!p.regionMatches(true, 0, "pkg:", 0, 4)) {
            return malformed("purl must start with 'pkg:': " + abbreviate(p));
        }
        p = p.substring(4);
        // 去掉 subpath（#...）与 qualifiers（?...），它们不参与组件身份
        int hash = p.indexOf('#');
        if (hash >= 0) {
            p = p.substring(0, hash);
        }
        int q = p.indexOf('?');
        if (q >= 0) {
            p = p.substring(0, q);
        }
        int slash = p.indexOf('/');
        if (slash <= 0) {
            return malformed("purl has no type or no name path: " + abbreviate(purl));
        }
        String type = p.substring(0, slash).toLowerCase();
        String path = p.substring(slash + 1);
        // 版本取最后一个路径段中 @ 之后的部分，身份只保留路径
        int lastSlash = path.lastIndexOf('/');
        int at = path.indexOf('@', lastSlash + 1);
        if (at >= 0) {
            path = path.substring(0, at);
        }
        List<String> segments = new ArrayList<>();
        for (String raw : path.split("/")) {
            if (!raw.isEmpty()) {
                segments.add(percentDecode(raw));
            }
        }
        if (segments.isEmpty() || segments.stream().anyMatch(String::isBlank)) {
            return malformed("purl has empty name segments: " + abbreviate(purl));
        }
        return switch (type) {
            case "maven" -> mavenIdentity(segments, purl);
            case "npm" -> npmIdentity(segments, purl);
            default -> new Result(Status.UNSUPPORTED_TYPE, type,
                    String.join("/", segments),
                    "unsupported purl type '" + type + "': identity kept generic, verdict will be UNKNOWN");
        };
    }

    /** Maven：pkg:maven/<groupId>/<artifactId>@... → 规范名 groupId:artifactId（小写）。 */
    private static Result mavenIdentity(List<String> segments, String purl) {
        if (segments.size() != 2) {
            return malformed("maven purl requires exactly <groupId>/<artifactId>: " + abbreviate(purl));
        }
        String canonical = (segments.get(0) + ":" + segments.get(1)).toLowerCase();
        return new Result(Status.OK, "maven", canonical, null);
    }

    /** npm：pkg:npm/<name> 或 pkg:npm/%40<scope>/<name> → 规范名 name 或 @scope/name（小写）。 */
    private static Result npmIdentity(List<String> segments, String purl) {
        if (segments.size() == 1) {
            return new Result(Status.OK, "npm", segments.get(0).toLowerCase(), null);
        }
        if (segments.size() == 2 && segments.get(0).startsWith("@")) {
            String canonical = (segments.get(0) + "/" + segments.get(1)).toLowerCase();
            return new Result(Status.OK, "npm", canonical, null);
        }
        return malformed("npm purl must be <name> or %40<scope>/<name>: " + abbreviate(purl));
    }

    private static Result malformed(String detail) {
        return new Result(Status.MALFORMED, null, null, detail);
    }

    /** 仅处理 %XX 百分号解码（UTF-8）；非法序列原样保留，不因此判畸形。 */
    private static String percentDecode(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(s.length());
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && isHex(s, i)) {
                bytes.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                i += 2;
                continue;
            }
            out.append(flush(bytes));
            out.append(c);
        }
        out.append(flush(bytes));
        return out.toString();
    }

    private static boolean isHex(String s, int i) {
        return i + 2 < s.length()
                && Character.digit(s.charAt(i + 1), 16) >= 0
                && Character.digit(s.charAt(i + 2), 16) >= 0;
    }

    private static String flush(ByteArrayOutputStream bytes) {
        if (bytes.size() == 0) {
            return "";
        }
        String decoded = bytes.toString(StandardCharsets.UTF_8);
        bytes.reset();
        return decoded;
    }

    private static String abbreviate(String text) {
        return text.length() <= 80 ? text : text.substring(0, 80) + "...";
    }
}
