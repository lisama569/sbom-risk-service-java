package com.github.lisama569.sbomriskservicejava.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.Ecosystems;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.RejectedItem;
import com.github.lisama569.sbomriskservicejava.version.SemVer;
import com.github.lisama569.sbomriskservicejava.version.VersionParseException;

/**
 * 把各格式中的单个条目节点归一为 {@link Component}，字段缺失/非法时给出区分原因。
 * <p>组件身份优先级：
 * <ol>
 *   <li><b>purl（包坐标）优先</b>：maven 坐标归一为 {@code groupId:artifactId}，
 *       npm 坐标归一为 {@code name} 或 {@code @scope/name}（均小写），
 *       与规则库登记的写法对齐；等价写法的坐标归一到同一身份，去重/幂等自然生效；</li>
 *   <li><b>不支持的坐标类型</b>：保留通用身份（生态=purl 类型），不当普通名字处理，
 *       判定时因生态不受支持而归入 UNKNOWN；</li>
 *   <li><b>畸形 purl</b>：条目拒绝，原因 {@link RejectReason#MALFORMED_PACKAGE_URL}；</li>
 *   <li><b>无 purl</b>：退回名称 + ecosystems 推断；maven 名称中
 *       {@code group/artifact} 等价写法归一为 {@code group:artifact}，
 *       maven/npm 名称统一小写，其余生态保留原始写法。</li>
 * </ol>
 */
final class ComponentNormalizer {

    private ComponentNormalizer() {
    }

    /**
     * 归一化一个条目。
     *
     * @param index      条目下标
     * @param name       名称原文（可能为 null/空白；有合法 purl 时不强制要求）
     * @param version    版本原文（可能为 null/空白）
     * @param purl       可选的 purl，存在时作为组件身份的权威来源
     * @param ecosystems 可选的 ecosystems 数组（CycloneDX 1.5）
     * @return 归一结果，成功取 component，失败取 rejected（互斥）
     */
    static Normalized normalize(int index, String name, String version, String purl, JsonNode ecosystems) {
        String cleanVersion = version == null ? null : version.trim();
        if (cleanVersion == null || cleanVersion.isEmpty()) {
            return new Normalized(null, new RejectedItem(
                    index, RejectReason.MISSING_COMPONENT_VERSION,
                    "component at index " + index + " has no version"));
        }
        try {
            SemVer.parse(cleanVersion);
        } catch (VersionParseException e) {
            return new Normalized(null, new RejectedItem(
                    index, RejectReason.MALFORMED_VERSION,
                    "component at index " + index + " has malformed version '"
                            + cleanVersion + "': " + e.getMessage()));
        }

        if (purl != null && !purl.isBlank()) {
            PackageUrl.Result coord = PackageUrl.parse(purl);
            if (coord.status() == PackageUrl.Status.MALFORMED) {
                return new Normalized(null, new RejectedItem(
                        index, RejectReason.MALFORMED_PACKAGE_URL,
                        "component at index " + index + " has unresolvable purl: "
                                + coord.detail()));
            }
            // OK：受支持生态的规范身份；UNSUPPORTED_TYPE：通用身份，判定层归入 UNKNOWN
            return new Normalized(
                    new Component(coord.ecosystem(), coord.canonicalName(), cleanVersion), null);
        }

        String cleanName = name == null ? null : name.trim();
        if (cleanName == null || cleanName.isEmpty()) {
            return new Normalized(null, new RejectedItem(
                    index, RejectReason.MISSING_COMPONENT_NAME,
                    "component at index " + index + " has no name"));
        }
        String ecosystem = resolveEcosystem(ecosystems);
        return new Normalized(
                new Component(ecosystem, canonicalizeName(ecosystem, cleanName), cleanVersion), null);
    }

    /** 生态取 ecosystems 数组首项，无则 unknown。 */
    private static String resolveEcosystem(JsonNode ecosystems) {
        if (ecosystems != null && ecosystems.isArray() && !ecosystems.isEmpty()) {
            JsonNode first = ecosystems.get(0);
            if (first != null && !first.asText().isBlank()) {
                return Ecosystems.normalize(first.asText());
            }
        }
        return Ecosystems.UNKNOWN;
    }

    /**
     * 按生态归一名称写法：maven 的 {@code group/artifact} 等价写法统一为
     * {@code group:artifact}；maven/npm 名称小写（两个生态的名称均不区分大小写）；
     * 其余生态不做大小写假设，保留原始写法。
     */
    private static String canonicalizeName(String ecosystem, String name) {
        return switch (ecosystem) {
            case "maven" -> name.replace('/', ':').toLowerCase();
            case "npm" -> name.toLowerCase();
            default -> name;
        };
    }

    /** 归一结果：component 与 rejected 必有且仅有一个非 null。 */
    record Normalized(Component component, RejectedItem rejected) {
        boolean ok() {
            return component != null;
        }
    }
}
