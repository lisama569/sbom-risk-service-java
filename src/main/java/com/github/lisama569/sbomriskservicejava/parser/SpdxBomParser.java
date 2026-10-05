package com.github.lisama569.sbomriskservicejava.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.RejectedItem;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import com.github.lisama569.sbomriskservicejava.model.UnresolvedComponent;

import java.util.ArrayList;
import java.util.List;

/**
 * SPDX 2.3 JSON 解析器。组件位于顶层 {@code packages} 数组，每项读取
 * {@code name}、{@code versionInfo}；生态从 {@code externalRefs} 中
 * {@code referenceType == "purl"} 的 {@code referenceLocator}（如 pkg:maven/...）推断。
 */
@org.springframework.stereotype.Component
public class SpdxBomParser implements SbomParser {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean supports(SbomFormat format) {
        return format == SbomFormat.SPDX_JSON;
    }

    @Override
    public ParseResult parse(String rawContent) {
        JsonNode root = readRoot(rawContent);
        JsonNode packages = root.get("packages");
        if (packages == null) {
            throw new SbomParseException("SPDX document is missing required 'packages' array");
        }
        if (!packages.isArray()) {
            throw new SbomParseException("SPDX 'packages' must be an array");
        }
        List<Component> accepted = new ArrayList<>();
        List<RejectedItem> rejected = new ArrayList<>();
        List<UnresolvedComponent> unresolved = new ArrayList<>();
        for (int i = 0; i < packages.size(); i++) {
            JsonNode node = packages.get(i);
            if (node == null || !node.isObject()) {
                rejected.add(new RejectedItem(i, RejectReason.MISSING_COMPONENT_NAME,
                        "packages[" + i + "] is not a JSON object"));
                unresolved.add(new UnresolvedComponent("unknown::?@?",
                        "UNKNOWN:missing-component-name"));
                continue;
            }
            String name = text(node, "name");
            String version = text(node, "versionInfo");
            String purl = extractPurl(node.get("externalRefs"));
            ComponentNormalizer.Normalized n =
                    ComponentNormalizer.normalize(i, name, version, purl, null);
            if (n.ok()) {
                accepted.add(n.component());
            } else {
                rejected.add(n.rejected());
                unresolved.add(n.unresolved());
            }
        }
        return new ParseResult(List.copyOf(accepted), List.copyOf(rejected),
                List.copyOf(unresolved));
    }

    /** 从 externalRefs 数组中取 referenceType=purl 的 referenceLocator。 */
    private String extractPurl(JsonNode externalRefs) {
        if (externalRefs == null || !externalRefs.isArray()) {
            return null;
        }
        for (JsonNode ref : externalRefs) {
            if (ref != null && ref.isObject()
                    && "purl".equalsIgnoreCase(text(ref, "referenceType"))) {
                return text(ref, "referenceLocator");
            }
        }
        return null;
    }

    private JsonNode readRoot(String rawContent) {
        try {
            JsonNode root = objectMapper.readTree(rawContent);
            if (root == null || !root.isObject()) {
                throw new SbomParseException("SPDX document root must be a JSON object");
            }
            return root;
        } catch (JsonProcessingException e) {
            throw new SbomParseException("invalid JSON in SPDX document: " + e.getOriginalMessage(), e);
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
