package com.github.lisama569.sbomriskservicejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.sbomriskservicejava.exception.SbomIngestionException;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Parser for CycloneDX JSON documents ({@code bomFormat == "CycloneDX"}).
 *
 * <p>Document-level problems (not an object, wrong bomFormat, missing or
 * non-array {@code components}) fail the whole document. Individual malformed
 * entries are returned so they can be rejected per-entry without dropping the
 * remaining entries.
 */
@Component
public class CycloneDxParser implements SbomParser {

    @Override
    public SbomFormat format() {
        return SbomFormat.CYCLONEDX_JSON;
    }

    @Override
    public String extractDocumentId(JsonNode root) {
        JsonNode serialNumber = root.get("serialNumber");
        if (serialNumber != null && serialNumber.isTextual() && !serialNumber.asText().isBlank()) {
            return serialNumber.asText().trim();
        }
        return null;
    }

    @Override
    public List<ParsedEntry> extractEntries(JsonNode root) {
        JsonNode components = root.get("components");
        if (components == null || components.isNull()) {
            throw new SbomIngestionException(RejectReason.MISSING_COMPONENTS,
                    "CycloneDX document has no 'components' array");
        }
        if (!components.isArray()) {
            throw new SbomIngestionException(RejectReason.MISSING_COMPONENTS,
                    "CycloneDX 'components' must be an array");
        }
        List<ParsedEntry> entries = new ArrayList<>();
        for (int i = 0; i < components.size(); i++) {
            JsonNode node = components.get(i);
            if (!node.isObject()) {
                entries.add(new ParsedEntry(i, null, null, null, null, null));
                continue;
            }
            entries.add(new ParsedEntry(
                    i,
                    textOrNull(node, "name"),
                    textOrNull(node, "version"),
                    textOrNull(node, "purl"),
                    extractEcosystem(node),
                    extractLicense(node)));
        }
        return entries;
    }

    /**
     * Derives the package ecosystem from the purl. CycloneDX's top-level
     * {@code type} is a component classification (library/framework/...),
     * not a package ecosystem, so it must not be used as one.
     */
    private static String extractEcosystem(JsonNode node) {
        String purl = textOrNull(node, "purl");
        if (purl == null) {
            return null;
        }
        String rest = purl.startsWith("pkg:") ? purl.substring(4) : purl;
        int slash = rest.indexOf('/');
        String type = slash >= 0 ? rest.substring(0, slash) : rest;
        int question = type.indexOf('?');
        if (question >= 0) {
            type = type.substring(0, question);
        }
        return type.isBlank() ? null : type.trim().toLowerCase();
    }

    private static String extractLicense(JsonNode node) {
        JsonNode licenses = node.get("licenses");
        if (licenses != null && licenses.isArray() && !licenses.isEmpty()) {
            JsonNode first = licenses.get(0);
            JsonNode expression = first.get("expression");
            if (expression != null && expression.isTextual()) {
                return expression.asText();
            }
            JsonNode license = first.get("license");
            if (license != null && license.isObject()) {
                JsonNode id = license.get("id");
                if (id != null && id.isTextual()) {
                    return id.asText();
                }
                JsonNode name = license.get("name");
                if (name != null && name.isTextual()) {
                    return name.asText();
                }
            }
        }
        return null;
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value != null && value.isTextual() && !value.asText().isBlank()) {
            return value.asText().trim();
        }
        return null;
    }
}
