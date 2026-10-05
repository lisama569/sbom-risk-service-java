package com.github.lisama569.sbomriskservicejava.model;

import java.util.Objects;

/**
 * 归一化后的统一组件模型。
 *
 * @param ecosystem       生态，如 maven/npm/pypi，缺失时为 unknown
 * @param name            组件名（必填，已按生态归一：maven 为 groupId:artifactId，npm 小写）
 * @param version         版本号原文（必填，需可解析）
 * @param identityReliable 身份是否来自可靠坐标：清单携带了 purl 但解析不出可靠身份时为
 *                        {@code false}，此类组件判定结论一律为 UNKNOWN，绝不默认安全
 */
public record Component(String ecosystem, String name, String version, boolean identityReliable) {

    public Component {
        Objects.requireNonNull(name, "component name");
        Objects.requireNonNull(version, "component version");
    }

    /** 便捷构造：身份可靠（无 purl 或 purl 解析成功的常规条目）。 */
    public Component(String ecosystem, String name, String version) {
        this(ecosystem, name, version, true);
    }

    /** 去重/幂等使用的稳定键。 */
    public String key() {
        return ecosystem + "::" + name + "@" + version;
    }
}
