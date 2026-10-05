package com.github.lisama569.sbomriskservicejava.parser;

/**
 * 包坐标（Package URL, purl）解析器。
 * <p>支持的坐标类型：
 * <ul>
 *   <li>{@code pkg:maven/<groupId>/<artifactId>@<version>} → 身份名 {@code groupId:artifactId}；</li>
 *   <li>{@code pkg:npm/[<@scope>/]<name>@<version>} → 身份名 {@code @scope/name} 或 {@code name}。</li>
 * </ul>
 * 其余类型（pypi、golang 等）返回 {@link Unsupported}，由上层给出可区分的处理，
 * 绝不当作普通名字混入。
 */
public final class PurlParser {

    private PurlParser() {
    }

    /** 解析结果三态：已解析 / 类型不支持 / 坐标畸形。 */
    public sealed interface Result permits Resolved, Unsupported, Malformed {
    }

    /** 解析成功，得到可靠身份。 */
    public record Resolved(PackageCoordinate coordinate) implements Result {
    }

    /**
     * 坐标类型当前不支持（可区分处理，不当作可判定组件混入）。
     *
     * @param type    坐标类型（小写），如 pypi/golang
     * @param rawName 从坐标中解析到的名称段（类型不支持，未做 maven/npm 式身份归一），
     *                可能为 null；仅用于在报告中以 UNKNOWN 条目展示
     * @param version 坐标中携带的版本，可能为 null
     */
    public record Unsupported(String type, String rawName, String version) implements Result {
    }

    /** 坐标写法畸形，无法解析出可靠身份。 */
    public record Malformed(String detail) implements Result {
    }

    /** 当前支持、可解析出可靠身份的坐标类型。 */
    public static final java.util.Set<String> SUPPORTED_TYPES = java.util.Set.of("maven", "npm");

    /**
     * 解析 purl 原文。
     * <p>等价写法归一规则：
     * <ul>
     *   <li>scheme（{@code pkg:}）大小写不敏感；type 一律小写；</li>
     *   <li>qualifiers（{@code ?...}）与 subpath（{@code #...}）不参与身份，直接剥离；</li>
     *   <li>各段做百分号解码（{@code %40} → {@code @} 等），{@code +} 保持原样；</li>
     *   <li>maven：{@code 命名空间:名称}；npm：名称小写，作用域段补全 {@code @} 前缀。</li>
     * </ul>
     *
     * @param purl purl 原文（非 null、非空白，调用方保证）
     * @return 三态结果
     */
    public static Result parse(String purl) {
        String p = purl.trim();
        if (p.regionMatches(true, 0, "pkg:", 0, 4)) {
            p = p.substring(4);
        } else {
            return new Malformed("purl must start with 'pkg:' scheme: " + abbreviate(purl));
        }
        // qualifiers / subpath 不参与身份
        int q = p.indexOf('?');
        if (q >= 0) {
            p = p.substring(0, q);
        }
        int h = p.indexOf('#');
        if (h >= 0) {
            p = p.substring(0, h);
        }
        int slash = p.indexOf('/');
        if (slash <= 0) {
            return new Malformed("purl has no type or no name segment: " + abbreviate(purl));
        }
        String type = p.substring(0, slash).toLowerCase();
        String rest = p.substring(slash + 1);
        // 版本取最后一个 @ 之后（名称段本身可能以 @ 开头，如 npm 作用域）
        String version = null;
        int at = rest.lastIndexOf('@');
        if (at > 0) {
            version = percentDecode(rest.substring(at + 1));
            rest = rest.substring(0, at);
        }
        String[] segments = rest.split("/");
        String name = percentDecode(segments[segments.length - 1]);
        String namespace = null;
        if (segments.length > 1) {
            StringBuilder ns = new StringBuilder();
            for (int i = 0; i < segments.length - 1; i++) {
                String seg = percentDecode(segments[i]);
                if (seg.isBlank()) {
                    // 空命名空间段对支持类型是畸形；不支持类型只做可区分拒绝，不继续校验
                    if (SUPPORTED_TYPES.contains(type)) {
                        return new Malformed("purl has empty namespace segment: " + abbreviate(purl));
                    }
                }
                if (ns.length() > 0) {
                    ns.append('/');
                }
                ns.append(seg);
            }
            namespace = ns.toString();
        }
        if (!SUPPORTED_TYPES.contains(type)) {
            // 不支持类型：携带原文名称与版本，供报告以 UNKNOWN 条目展示，绝不丢弃
            String rawName = (namespace == null || namespace.isBlank()) ? name : namespace + "/" + name;
            return new Unsupported(type, rawName, version);
        }
        if (name.isBlank() || name.startsWith("@")) {
            // 名称为空，或名称段以 @ 开头（@ 只允许出现在 npm 作用域段）
            return new Malformed("purl has empty or illegal name segment: " + abbreviate(purl));
        }
        return switch (type) {
            case "maven" -> {
                if (namespace == null) {
                    yield new Malformed("maven purl requires groupId namespace: " + abbreviate(purl));
                }
                // Maven 坐标大小写不敏感，整体小写归一到稳定身份
                String canonical = IdentityNormalizer.name("maven", namespace + "/" + name);
                yield new Resolved(new PackageCoordinate("maven", canonical, version));
            }
            case "npm" -> {
                String canonical = IdentityNormalizer.name("npm",
                        namespace == null ? name : namespace + "/" + name);
                yield new Resolved(new PackageCoordinate("npm", canonical, version));
            }
            default -> new Unsupported(type, name, version); // 不可达：SUPPORTED_TYPES 已拦截
        };
    }

    /** 仅做 %XX 百分号解码；非法序列与原样字符（含 +）保持不变。 */
    static String percentDecode(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.append((char) ((hi << 4) | lo));
                    i += 2;
                    continue;
                }
            }
            out.append(c);
        }
        return out.toString();
    }

    private static String abbreviate(String text) {
        return text.length() <= 80 ? text : text.substring(0, 80) + "...";
    }
}
