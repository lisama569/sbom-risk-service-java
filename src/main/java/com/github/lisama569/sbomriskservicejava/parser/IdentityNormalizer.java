package com.github.lisama569.sbomriskservicejava.parser;

/**
 * 组件身份归一：把各种等价写法收敛到同一个稳定身份，使去重、幂等与规则匹配
 * 都以归一后的身份为准。
 * <ul>
 *   <li>maven：{@code groupId:artifactId}。组名与构件名之间允许 {@code :} 或 {@code /}
 *       分隔（如名字字段里直接写 {@code org.apache.logging.log4j/log4j-core}），
 *       组内分隔符允许 {@code .} 或 {@code /}；Maven 坐标按大小写不敏感归一
 *       （{@code Org.Apache:Log4j-Core} 与 {@code org.apache:log4j-core} 同一身份）；</li>
 *   <li>npm：名称与作用域一律小写，作用域缺 {@code @} 时补全（{@code angular/core}
 *       → {@code @angular/core}）；</li>
 *   <li>其余生态：trim 后原样保留（生态不同身份严格隔离，不串号）。</li>
 * </ul>
 */
public final class IdentityNormalizer {

    private IdentityNormalizer() {
    }

    /** 生态名归一：小写、去空白；null/空白归为 unknown。 */
    public static String ecosystem(String raw) {
        if (raw == null || raw.isBlank()) {
            return "unknown";
        }
        return raw.trim().toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * 按生态把名称原文归一为稳定身份名。
     *
     * @param ecosystemRaw 生态原文（本方法内部会先做生态归一）
     * @param rawName      名称原文（非空白，调用方保证）
     * @return 归一后的身份名
     */
    public static String name(String ecosystemRaw, String rawName) {
        String eco = ecosystem(ecosystemRaw);
        String n = rawName.trim();
        return switch (eco) {
            case "maven" -> mavenName(n);
            case "npm" -> npmName(n);
            default -> n;
        };
    }

    /**
     * Maven 身份归一：{@code groupId:artifactId}。
     * <p>等价写法：
     * <ul>
     *   <li>组名/构件名分隔符：{@code :} 或 {@code /}（最后一个分隔符左边为组名）；</li>
     *   <li>组名内部分隔符：{@code .} 与 {@code /} 等价（{@code org/apache/log4j} →
     *       {@code org.apache.log4j}）；</li>
     *   <li>大小写不敏感：整体转小写形成稳定身份。</li>
     * </ul>
     * 没有任何分隔符（无法可靠拆出 groupId）时只做小写归一。
     */
    static String mavenName(String n) {
        String s = n.trim();
        int colon = s.lastIndexOf(':');
        int slash = s.lastIndexOf('/');
        int sep = Math.max(colon, slash);
        if (sep > 0) {
            String group = s.substring(0, sep).replace('/', '.');
            String artifact = s.substring(sep + 1);
            s = group + ":" + artifact;
        }
        return s.toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * npm 身份归一：名称小写；带作用域时作用域补全 {@code @} 并小写
     * （{@code Angular/Core} → {@code @angular/core}，{@code @Angular/Core} 同样）。
     */
    static String npmName(String n) {
        String s = n.trim();
        int slash = s.indexOf('/');
        if (slash > 0) {
            String scope = s.substring(0, slash);
            String pkg = s.substring(slash + 1);
            if (!scope.startsWith("@")) {
                scope = "@" + scope;
            }
            return (scope + "/" + pkg).toLowerCase(java.util.Locale.ROOT);
        }
        return s.toLowerCase(java.util.Locale.ROOT);
    }
}
