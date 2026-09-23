package com.github.lisama569.sbomriskservicejava.web;

import com.github.lisama569.sbomriskservicejava.exception.NotFoundException;
import com.github.lisama569.sbomriskservicejava.ingest.SbomIngestionService;
import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.IngestResult;
import com.github.lisama569.sbomriskservicejava.model.IngestStatus;
import com.github.lisama569.sbomriskservicejava.model.RiskAssessment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * HTTP API for SBOM ingestion and risk assessment.
 *
 * <p>Status mapping for {@code POST /api/v1/sboms}: 200 for ACCEPTED, 207 for
 * PARTIAL (per-entry rejections kept inside the body), 422 for FAILED (every
 * entry rejected; nothing ingested). Document-level failures are 400 via the
 * exception handler.
 */
@RestController
@RequestMapping("/api/v1")
public class SbomController {

    private final SbomIngestionService service;

    public SbomController(SbomIngestionService service) {
        this.service = service;
    }

    @PostMapping("/sboms")
    public ResponseEntity<IngestResult> ingest(
            @RequestBody IngestRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey) {
        if (request == null) {
            throw new com.github.lisama569.sbomriskservicejava.exception.SbomIngestionException(
                    com.github.lisama569.sbomriskservicejava.model.RejectReason.MISSING_DOCUMENT,
                    "request body is required");
        }
        String clientDocId = firstNonBlank(idempotencyKey, request.documentId());
        IngestResult result = service.ingest(request.content(), clientDocId);
        HttpStatus status = result.status() == IngestStatus.ACCEPTED ? HttpStatus.OK
                : result.status() == IngestStatus.PARTIAL ? HttpStatus.MULTI_STATUS
                : HttpStatus.UNPROCESSABLE_ENTITY;
        return ResponseEntity.status(status).body(result);
    }

    @GetMapping("/components")
    public List<Component> listComponents() {
        return service.listComponents();
    }

    /**
     * Assess one component. The key is taken from the {@code key} query
     * parameter because component keys are package URLs containing slashes.
     */
    @GetMapping("/components/risk")
    public RiskAssessment componentRisk(@org.springframework.web.bind.annotation.RequestParam("key") String key) {
        String decoded = URLDecoder.decode(key, StandardCharsets.UTF_8);
        return service.assessComponent(decoded)
                .orElseThrow(() -> new NotFoundException("no component with key: " + decoded));
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        return (b != null && !b.isBlank()) ? b : null;
    }
}
