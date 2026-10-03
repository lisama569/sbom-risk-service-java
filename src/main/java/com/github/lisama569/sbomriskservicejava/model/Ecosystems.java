package com.github.lisama569.sbomriskservicejava.model;

import java.util.Set;

/**
 * 生态（包生态系统）的统一认知：
 * <ul>
 *   <li>{@link #isSupported} 判定服务当前能为哪些生态提供可靠身份与规则判定
 *       （目前：maven、npm）；</li>
 *   <li>不支持的生态与 {@link #UNKNOWN} 一样，组件身份视为不可靠，
 *       风险判定一律落入 {@link RiskLevel#UNKNOWN}，绝不默认安全。</li>
 * </ul>
 */
public final class Ecosystems {

    /** 无法从清单条目推断生态时使用的占位值。 */
    public static final String UNKNOWN = "unknown";

    private static final Set<String> SUPPORTED = Set.of("maven", "npm");

    private Ecosystems() {
    }

    /** 生态是否受支持（可建立可靠组件身份并参与规则判定）。 */
    public static boolean isSupported(String ecosystem) {
        return ecosystem != null && SUPPORTED.contains(ecosystem.trim().toLowerCase());
    }

    /** 归一化生态写法（去空白、小写）；空值归一为 {@link #UNKNOWN}。 */
    public static String normalize(String ecosystem) {
        if (ecosystem == null || ecosystem.isBlank()) {
            return UNKNOWN;
        }
        return ecosystem.trim().toLowerCase();
    }
}
