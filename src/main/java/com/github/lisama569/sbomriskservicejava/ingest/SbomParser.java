package com.github.lisama569.sbomriskservicejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;

import java.util.List;

/**
 * Parser for one SBOM format.
 */
public interface SbomParser {

    SbomFormat format();

    /** Extract a stable document id from the document, or null if absent. */
    String extractDocumentId(JsonNode root);

    /**
     * Parse document-level structure and entries. Document-level problems
     * (malformed JSON, unknown format, missing components array) are raised
     * as document failures; entry-level problems are returned as entries and
     * rejected later so that partial success remains possible.
     */
    List<ParsedEntry> extractEntries(JsonNode root);
}
