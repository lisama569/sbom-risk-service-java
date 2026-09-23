package com.github.lisama569.sbomriskservicejava.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectedItem;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;

import java.util.ArrayList;
import java.util.List;

/**
 * CycloneDX JSON 解析器。组件位于顶层 {@code components} 数组，每项读取
 * {@code name}、{@code version}、{@code purl}、{@code ecosystems}。
 * <p>文档畸形（JSON 非法、根不是对象、components 缺失或不是数组）直接抛出
 * {@link SbomParseException}；条目级问题逐条收集，绝不静默跳过。
 */
@org.springframework.stereotype.Component
public class CycloneDxBomParser implements SbomParser {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean supports(SbomFormat format) {
        return format == SbomFormat.CYCLONEDX_JSON;
    }

    @Override
    public ParseResult parse(String rawContent) {
        JsonNode root = readRoot(rawContent);
        JsonNode components = root.get("components");
        if (components == null) {
            throw new SbomParseException("CycloneDX document is missing required 'components' array");
        }
        if (!components.isArray()) {
            throw new SbomParseException("CycloneDX 'components' must be an array");
        }
        List<Component> accepted = new ArrayList<>();
        List<RejectedItem> rejected = new ArrayList<>();
        for (int i = 0; i < components.size(); i++) {
            JsonNode node = components.get(i);
            if (node == null || !node.isObject()) {
                rejected.add(new RejectedItem(i,
                        com.github.lisama569.sbomriskservicejava.model.RejectReason.MISSING_COMPONENT_NAME,
                        "components[" + i + "] is not a JSON object"));
                continue;
            }
            String name = text(node, "name");
            String version = text(node, "version");
            String purl = text(node, "purl");
            JsonNode ecosystems = node.get("ecosystems");
            ComponentNormalizer.Normalized n =
                    ComponentNormalizer.normalize(i, name, version, purl, ecosystems);
            if (n.ok()) {
                accepted.add(n.component());
            } else {
                rejected.add(n.rejected());
            }
        }
        return new ParseResult(List.copyOf(accepted), List.copyOf(rejected));
    }

    private JsonNode readRoot(String rawContent) {
        try {
            JsonNode root = objectMapper.readTree(rawContent);
            if (root == null || !root.isObject()) {
                throw new SbomParseException("CycloneDX document root must be a JSON object");
            }
            return root;
        } catch (JsonProcessingException e) {
            throw new SbomParseException("invalid JSON in CycloneDX document: " + e.getOriginalMessage(), e);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        return v.asText();
    }
}
