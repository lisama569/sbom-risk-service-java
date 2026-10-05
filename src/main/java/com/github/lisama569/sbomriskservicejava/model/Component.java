package com.github.lisama569.sbomriskservicejava.model;

import java.util.Objects;

/**
 * 归一化后的统一组件模型。
 *
 * @param ecosystem 生态，如 maven/npm/pypi，缺失时为 unknown
 * @param name      组件名（必填，已做身份归一）
 * @param version   版本号原文（必填，需可解析）
 * @param coordinateNote 坐标身份备注；非 null 表示该组件并非来自可靠坐标
 *                      （如 purl 畸形，只能回退字段法），判定时一律 UNKNOWN，
 *                      即使字段上标着 maven 也不得放行为 CLEAN
 */
public record Component(String ecosystem, String name, String version, String coordinateNote) {

    /** 坐标身份可靠（标准构造）。 */
    public Component(String ecosystem, String name, String version) {
        this(ecosystem, name, version, null);
    }

    public Component {
        Objects.requireNonNull(name, "component name");
        Objects.requireNonNull(version, "component version");
    }

    /** 去重/幂等使用的稳定键。 */
    public String key() {
        return ecosystem + "::" + name + "@" + version;
    }

    /** 坐标身份是否可靠；不可靠的组件无法判定（结论为 UNKNOWN）。 */
    public boolean identityReliable() {
        return coordinateNote == null;
    }
}
