package com.github.lisama569.sbomriskservicejava.web;

/**
 * Generic error body for document-level failures.
 */
public record ErrorResponse(
        String error,
        String reason,
        String detail,
        String documentId
) {
}
