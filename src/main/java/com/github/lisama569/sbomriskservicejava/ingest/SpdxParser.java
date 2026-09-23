package com.github.lisama569.sbomriskservicejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.sbomriskservicejava.exception.SbomIngestionException;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Parser for SPDX 2.x JSON documents ({@code spdxVersion} starts with "SPDX-").
 *
 * <p>Components are read from {@code packages[]}; name comes from
 * {@code name}, version from {@code versionInfo}, the declared license from
 * {@code licenseDeclared}, and the package URL and ecosystem from the
 * {@code externalRefs} entry of category PACKAGE-MANAGER / type purl.
 */
@Component
public class SpdxParser implements SbomParser {

    @Override
    public SbomFormat format() {
        return SbomFormat.SPDX_JSON;
    }

    @Override
    public String extractDocumentId(JsonNode root) {
        JsonNode namespace = root.get("documentNamespace");
        if (namespace != null && namespace.isTextual() && !namespace.asText().isBlank()) {
            return namespace.asText().trim();
        }
        JsonNode id = root.get("SPDXID");
        if (id != null && id.isTextual() && !id.asText().isBlank()) {
            return id.asText().trim();
        }
        return null;
    }

    @Override
    public List<ParsedEntry> extractEntries(JsonNode root) {
        JsonNode packages = root.get("packages");
        if (packages == null || packages.isNull()) {
            throw new SbomIngestionException(RejectReason.MISSING_COMPONENTS,
                    "SPDX document has no 'packages' array");
        }
        if (!packages.isArray()) {
            throw new SbomIngestionException(RejectReason.MISSING_COMPONENTS,
                    "SPDX 'packages' must be an array");
        }
        List<ParsedEntry> entries = new ArrayList<>();
        for (int i = 0; i < packages.size(); i++) {
            JsonNode node = packages.get(i);
            if (!node.isObject()) {
                entries.add(new ParsedEntry(i, null, null, null, null, null));
                continue;
            }
            String purl = null;
            String ecosystem = null;
            JsonNode refs = node.get("externalRefs");
            if (refs != null && refs.isArray()) {
                for (JsonNode ref : refs) {
                    if (ref.path("referenceType").asText("").equalsIgnoreCase("purl")) {
                        purl = textOrNull(ref, "referenceLocator");
                        ecosystem = extractEcosystem(purl);
                        break;
                    }
                }
            }
            entries.add(new ParsedEntry(
                    i,
                    textOrNull(node, "name"),
                    textOrNull(node, "versionInfo"),
                    purl,
                    ecosystem,
                    textOrNull(node, "licenseDeclared")));
        }
        return entries;
    }

    private static String extractEcosystem(String purl) {
        if (purl == null) {
            return null;
        }
        String rest = purl.trim();
        if (rest.startsWith("pkg:")) {
            rest = rest.substring(4);
        }
        int slash = rest.indexOf('/');
        String type = slash >= 0 ? rest.substring(0, slash) : rest;
        int question = type.indexOf('?');
        if (question >= 0) {
            type = type.substring(0, question);
        }
        return type.isBlank() ? null : type.trim().toLowerCase();
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value != null && value.isTextual() && !value.asText().isBlank()) {
            String text = value.asText().trim();
            if ("NOASSERTION".equals(text) || "NONE".equals(text)) {
                return null;
            }
            return text;
        }
        return null;
    }
}
