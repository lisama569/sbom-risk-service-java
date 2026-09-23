package com.github.lisama569.sbomriskservicejava.web;

/**
 * Ingestion request: the raw SBOM content comes inline with the HTTP request,
 * simulating software composition data. formatHint may be null (auto detect).
 */
public record IngestRequest(
        String documentId,
        String format,
        String content
) {
}
