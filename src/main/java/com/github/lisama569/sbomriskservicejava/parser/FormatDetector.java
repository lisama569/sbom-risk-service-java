package com.github.lisama569.sbomriskservicejava.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import org.springframework.stereotype.Component;

/**
 * 根据 JSON 字段特征识别清单格式：
 * <ul>
 *   <li>{@code bomFormat == "CycloneDX"} → CycloneDX JSON；</li>
 *   <li>存在 {@code spdxVersion} 字段 → SPDX JSON；</li>
 *   <li>其余情况视为无法识别的格式。</li>
 * </ul>
 */
@Component
public class FormatDetector {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /** 识别格式；畸形 JSON 或无法识别时抛 {@link SbomParseException}。 */
    public SbomFormat detect(String rawContent) {
        if (rawContent == null || rawContent.trim().isEmpty()) {
            throw new SbomParseException("SBOM content is empty");
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(rawContent);
        } catch (JsonProcessingException e) {
            throw new SbomParseException("SBOM content is not valid JSON: " + e.getOriginalMessage(), e);
        }
        if (root == null || !root.isObject()) {
            throw new SbomParseException("SBOM root must be a JSON object");
        }
        JsonNode bomFormat = root.get("bomFormat");
        if (bomFormat != null && "CycloneDX".equalsIgnoreCase(bomFormat.asText())) {
            return SbomFormat.CYCLONEDX_JSON;
        }
        if (root.has("spdxVersion")) {
            return SbomFormat.SPDX_JSON;
        }
        throw new SbomParseException(
                "unrecognized SBOM format: neither CycloneDX (bomFormat) nor SPDX (spdxVersion) signature found");
    }
}
