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
     *
     * @param index     条目下标
     * @param name      名称原文（可能为 null/空白）
     * @param version   版本原文（可能为 null/空白）
     * @param purl      可选的 purl，用于补全生态
     * @param ecosystems 可选的 ecosystems 数组（CycloneDX 1.5）
     * @return 归一结果，成功取 component，失败取 rejected（互斥）
     */
    static Normalized normalize(int index, String name, String version, String purl, JsonNode ecosystems) {
        String cleanName = name == null ? null : name.trim();
        if (cleanName == null || cleanName.isEmpty()) {
            return new Normalized(null, new RejectedItem(
                    index, RejectReason.MISSING_COMPONENT_NAME,
                    "component at index " + index + " has no name"));
        }
        String cleanVersion = version == null ? null : version.trim();
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
        String ecosystem = resolveEcosystem(purl, ecosystems);
        return new Normalized(new Component(ecosystem, cleanName, cleanVersion), null);
    }

    /** 生态优先取 ecosystems 数组首项，其次从 purl 推断，均无则 unknown。 */
    private static String resolveEcosystem(String purl, JsonNode ecosystems) {
        if (ecosystems != null && ecosystems.isArray() && !ecosystems.isEmpty()) {
            JsonNode first = ecosystems.get(0);
            if (first != null && !first.asText().isBlank()) {
                return first.asText().trim().toLowerCase();
            }
        }
        if (purl != null && !purl.isBlank()) {
            String p = purl.trim();
            if (p.startsWith("pkg:")) {
                p = p.substring(4);
            }
            int slash = p.indexOf('/');
            String type = slash >= 0 ? p.substring(0, slash) : p;
            if (!type.isEmpty()) {
                return type.toLowerCase();
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
