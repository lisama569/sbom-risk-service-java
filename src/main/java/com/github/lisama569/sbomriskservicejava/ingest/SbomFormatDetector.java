package com.github.lisama569.sbomriskservicejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Detects the SBOM format of a parsed JSON document from its structural
 * markers: {@code bomFormat == "CycloneDX"} or an {@code spdxVersion} field
 * prefixed with {@code SPDX-}.
 */
@Component
public class SbomFormatDetector {

    private final Map<SbomFormat, SbomParser> parsers;

    public SbomFormatDetector(List<SbomParser> parserList) {
        Map<SbomFormat, SbomParser> map = new EnumMap<>(SbomFormat.class);
        for (SbomParser p : parserList) {
            map.put(p.format(), p);
        }
        this.parsers = Map.copyOf(map);
    }

    public SbomFormat detect(JsonNode root) {
        if (root == null || !root.isObject()) {
            return SbomFormat.UNKNOWN;
        }
        JsonNode bomFormat = root.get("bomFormat");
        if (bomFormat != null && bomFormat.isTextual()
                && "CycloneDX".equalsIgnoreCase(bomFormat.asText())) {
            return SbomFormat.CYCLONEDX_JSON;
        }
        JsonNode spdxVersion = root.get("spdxVersion");
        if (spdxVersion != null && spdxVersion.isTextual()
                && spdxVersion.asText().startsWith("SPDX-")) {
            return SbomFormat.SPDX_JSON;
        }
        return SbomFormat.UNKNOWN;
    }

    public SbomParser parserFor(SbomFormat format) {
        SbomParser parser = parsers.get(format);
        if (parser == null) {
            throw new IllegalStateException("no parser registered for format " + format);
        }
        return parser;
    }
}
