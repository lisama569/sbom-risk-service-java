package com.github.lisama569.sbomriskservicejava.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.RejectedItem;
import com.github.lisama569.sbomriskservicejava.version.SemVer;
import com.github.lisama569.sbomriskservicejava.version.VersionParseException;

/** 把各格式中的单个条目节点归一为 {@link Component}，字段缺失/非法时给出区分原因。 */
final class ComponentNormalizer {

    private ComponentNormalizer() {
    }

    /**
     * 归一化一个条目。
     * <p>身份解析顺序：
     * <ol>
     *   <li>purl 存在且为支持的坐标类型（maven/npm）→ 以坐标为可靠身份
     *       （生态 + 归一名称取自坐标；条目版本缺失时回退坐标版本）；</li>
     *   <li>purl 类型不支持 → 以 {@link RejectReason#UNSUPPORTED_PURL_TYPE} 明确拒绝，
     *       绝不当作普通名字混入；</li>
     *   <li>purl 畸形 → 坐标不可靠，回退到 name / ecosystems 字段
     *       （生态多为 unknown，风险判定会归入 UNKNOWN，不会默认安全）；</li>
     *   <li>无 purl → 使用 name 字段，生态取 ecosystems 首项，否则 unknown。</li>
     * </ol>
     *
     * @param index     条目下标
     * @param name      名称原文（可能为 null/空白）
     * @param version   版本原文（可能为 null/空白）
     * @param purl      可选的 purl，用于解析可靠身份
     * @param ecosystems 可选的 ecosystems 数组（CycloneDX 1.5）
     * @return 归一结果，成功取 component，失败取 rejected（互斥）
     */
    static Normalized normalize(int index, String name, String version, String purl, JsonNode ecosystems) {
        String cleanName = name == null ? null : name.trim();
        String cleanVersion = version == null ? null : version.trim();
        String ecosystem = null;

        if (purl != null && !purl.isBlank()) {
            switch (PurlParser.parse(purl)) {
                case PurlParser.Resolved resolved -> {
                    PackageCoordinate c = resolved.coordinate();
                    ecosystem = c.ecosystem();
                    cleanName = c.name();
                    if (cleanVersion == null || cleanVersion.isEmpty()) {
                        cleanVersion = c.version();
                    }
                }
                case PurlParser.Unsupported unsupported -> {
                    return new Normalized(null, new RejectedItem(
                            index, RejectReason.UNSUPPORTED_PURL_TYPE,
                            "component at index " + index + " uses unsupported purl type '"
                                    + unsupported.type() + "' (supported: "
                                    + PurlParser.SUPPORTED_TYPES + ")"));
                }
                case PurlParser.Malformed malformed -> {
                    // 坐标解析不出可靠身份：回退字段法，生态多为 unknown，
                    // 由风险判定归入 UNKNOWN，绝不默认安全
                }
            }
        }

        if (cleanName == null || cleanName.isEmpty()) {
            return new Normalized(null, new RejectedItem(
                    index, RejectReason.MISSING_COMPONENT_NAME,
                    "component at index " + index + " has no name"));
        }
        if (cleanVersion == null || cleanVersion.isEmpty()) {
            return new Normalized(null, new RejectedItem(
                    index, RejectReason.MISSING_COMPONENT_VERSION,
                    "component '" + cleanName + "' has no version"));
        }
        try {
            SemVer.parse(cleanVersion);
        } catch (VersionParseException e) {
            return new Normalized(null, new RejectedItem(
                    index, RejectReason.MALFORMED_VERSION,
                    "component '" + cleanName + "' has malformed version '"
                            + cleanVersion + "': " + e.getMessage()));
        }
        if (ecosystem == null) {
            ecosystem = resolveEcosystem(ecosystems);
        }
        return new Normalized(new Component(ecosystem, cleanName, cleanVersion), null);
    }

    /** 无可靠坐标时的生态来源：ecosystems 数组首项，否则 unknown。 */
    private static String resolveEcosystem(JsonNode ecosystems) {
        if (ecosystems != null && ecosystems.isArray() && !ecosystems.isEmpty()) {
            JsonNode first = ecosystems.get(0);
            if (first != null && !first.asText().isBlank()) {
                return first.asText().trim().toLowerCase();
            }
        }
        return "unknown";
    }

    /** 归一结果：component 与 rejected 必有且仅有一个非 null。 */
    record Normalized(Component component, RejectedItem rejected) {
        boolean ok() {
            return component != null;
        }
    }
}
