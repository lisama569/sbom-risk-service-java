package com.github.lisama569.sbomriskservicejava.model;

import java.util.Objects;

/**
 * 归一化后的统一组件模型。
 *
 * @param ecosystem 生态，如 maven/npm/pypi，缺失时为 unknown
 * @param name      组件名（必填）
 * @param version   版本号原文（必填，需可解析）
 */
public record Component(String ecosystem, String name, String version) {

    public Component {
        Objects.requireNonNull(name, "component name");
        Objects.requireNonNull(version, "component version");
    }

    /** 去重/幂等使用的稳定键。 */
    public String key() {
        return ecosystem + "::" + name + "@" + version;
    }
}
