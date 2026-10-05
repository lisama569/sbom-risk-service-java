package com.github.lisama569.sbomriskservicejava.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.RejectedItem;
import com.github.lisama569.sbomriskservicejava.model.UnresolvedComponent;
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
     *       同时生成 UNKNOWN 条目，报告里必须可见并抬高总体结论；</li>
     *   <li>purl 畸形 → 回退字段法，但组件标记为“坐标身份不可靠”，
     *       即使字段标着 maven，判定层也一律给 UNKNOWN，绝不放行为 CLEAN；</li>
     *   <li>无 purl → 使用 name 字段（按生态做等价写法归一），
     *       生态取 ecosystems 首项，否则 unknown。</li>
     * </ol>
     * 缺名称/缺版本/非法版本同样生成 paired 的拒绝原因 + UNKNOWN 条目，
     * 绝不允许“拒绝即消失”。
     */
    static Normalized normalize(int index, String name, String version, String purl, JsonNode ecosystems) {
        String cleanName = name == null ? null : name.trim();
        String cleanVersion = version == null ? null : version.trim();
        String ecosystem = null;
        String coordinateNote = null;

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
                    String eco = IdentityNormalizer.ecosystem(unsupported.type());
                    String displayName = unsupported.rawName() == null ? "?" : unsupported.rawName();
                    String displayVersion = unsupported.version() == null ? "?" : unsupported.version();
                    String key = unresolvedKey(eco, displayName, displayVersion);
                    String reason = "UNKNOWN:unsupported-coordinate-type:" + unsupported.type();
                    return reject(index, RejectReason.UNSUPPORTED_PURL_TYPE,
                            "component at index " + index + " uses unsupported purl type '"
                                    + unsupported.type() + "' (supported: "
                                    + PurlParser.SUPPORTED_TYPES + ")",
                            new UnresolvedComponent(key, reason));
                }
                case PurlParser.Malformed malformed -> {
                    // 坐标解析不出可靠身份：回退字段法，但标记身份不可靠，
                    // 由风险判定强制归入 UNKNOWN（即使字段标着 maven 也不放行）
                    coordinateNote = "malformed-purl:" + malformed.detail();
                }
            }
        }

        if (ecosystem == null) {
            ecosystem = resolveEcosystem(ecosystems);
        }
        // 字段法名称按生态做等价写法归一（斜杠/冒号分隔、大小写、npm 作用域）
        if (cleanName != null && !cleanName.isEmpty()) {
            cleanName = IdentityNormalizer.name(ecosystem, cleanName);
        }

        if (cleanName == null || cleanName.isEmpty()) {
            String key = unresolvedKey(ecosystem, "?", cleanVersion == null ? "?" : cleanVersion);
            return reject(index, RejectReason.MISSING_COMPONENT_NAME,
                    "component at index " + index + " has no name",
                    new UnresolvedComponent(key, "UNKNOWN:missing-component-name"));
        }
        if (cleanVersion == null || cleanVersion.isEmpty()) {
            String key = unresolvedKey(ecosystem, cleanName, "?");
            return reject(index, RejectReason.MISSING_COMPONENT_VERSION,
                    "component '" + cleanName + "' has no version",
                    new UnresolvedComponent(key, "UNKNOWN:missing-component-version:" + cleanName));
        }
        try {
            SemVer.parse(cleanVersion);
        } catch (VersionParseException e) {
            String key = unresolvedKey(ecosystem, cleanName, cleanVersion);
            return reject(index, RejectReason.MALFORMED_VERSION,
                    "component '" + cleanName + "' has malformed version '"
                            + cleanVersion + "': " + e.getMessage(),
                    new UnresolvedComponent(key,
                            "UNKNOWN:malformed-version:" + cleanName + "@" + cleanVersion));
        }
        return new Normalized(new Component(ecosystem, cleanName, cleanVersion, coordinateNote),
                null, null);
    }

    /** 无法判定条目的稳定标识（去重/报告排序用），缺失字段以 ? 占位。 */
    static String unresolvedKey(String ecosystem, String name, String version) {
        return IdentityNormalizer.ecosystem(ecosystem) + "::" + name + "@" + version;
    }

    private static Normalized reject(int index, RejectReason reason, String detail,
                                     UnresolvedComponent unresolved) {
        return new Normalized(null, new RejectedItem(index, reason, detail), unresolved);
    }

    /** 无可靠坐标时的生态来源：ecosystems 数组首项，否则 unknown。 */
    private static String resolveEcosystem(JsonNode ecosystems) {
        if (ecosystems != null && ecosystems.isArray() && !ecosystems.isEmpty()) {
            JsonNode first = ecosystems.get(0);
            if (first != null && !first.asText().isBlank()) {
                return IdentityNormalizer.ecosystem(first.asText());
            }
        }
        return "unknown";
    }

    /** 归一结果：成功取 component；失败取 rejected 与 unresolved（二者成对出现）。 */
    record Normalized(Component component, RejectedItem rejected,
                      UnresolvedComponent unresolved) {
        boolean ok() {
            return component != null;
        }
    }
}
