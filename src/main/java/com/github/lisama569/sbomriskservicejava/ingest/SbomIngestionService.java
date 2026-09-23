package com.github.lisama569.sbomriskservicejava.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.sbomriskservicejava.exception.SbomIngestionException;
import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.IngestResult;
import com.github.lisama569.sbomriskservicejava.model.IngestedComponent;
import com.github.lisama569.sbomriskservicejava.model.IngestStatus;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.RejectedEntry;
import com.github.lisama569.sbomriskservicejava.model.RiskAssessment;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import com.github.lisama569.sbomriskservicejava.rule.RuleEvaluator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Application service: ingests an inline SBOM payload, normalizes it into the
 * unified component model, enforces idempotency and performs risk assessment.
 */
@Service
public class SbomIngestionService {

    private static final Logger log = LoggerFactory.getLogger(SbomIngestionService.class);

    private final ObjectMapper objectMapper;
    private final SbomFormatDetector detector;
    private final Normalizer normalizer;
    private final ComponentStore store;
    private final IdempotencyGuard guard;
    private final RuleEvaluator evaluator;

    public SbomIngestionService(ObjectMapper objectMapper,
                                SbomFormatDetector detector,
                                Normalizer normalizer,
                                ComponentStore store,
                                IdempotencyGuard guard,
                                RuleEvaluator evaluator) {
        this.objectMapper = objectMapper;
        this.detector = detector;
        this.normalizer = normalizer;
        this.store = store;
        this.guard = guard;
        this.evaluator = evaluator;
    }

    /**
     * Ingest a raw SBOM payload.
     *
     * @param payload     raw JSON request body content
     * @param clientDocId client supplied idempotency key (header or request field)
     * @throws SbomIngestionException on document-level failure (nothing ingested)
     */
    public IngestResult ingest(String payload, String clientDocId) {
        if (payload == null || payload.isBlank()) {
            throw new SbomIngestionException(RejectReason.MISSING_DOCUMENT, "request 'content' is blank");
        }
        log.info("ingest start: clientDocId={}, payloadBytes={}", clientDocId, payload.length());

        JsonNode root = parseJson(payload);
        SbomFormat format = detector.detect(root);
        if (format == SbomFormat.UNKNOWN) {
            throw new SbomIngestionException(RejectReason.UNSUPPORTED_FORMAT,
                    "document is neither CycloneDX JSON (bomFormat=CycloneDX) nor SPDX 2.x JSON (spdxVersion=SPDX-*)");
        }
        SbomParser parser = detector.parserFor(format);
        String embeddedId = parser.extractDocumentId(root);
        String documentId = resolveDocumentId(clientDocId, embeddedId, payload);

        GuardedResult guarded = guard.execute(documentId, () -> doIngest(documentId, format, parser, root));
        IngestResult result = guarded.result();
        if (guarded.replayed()) {
            result = markReplay(result);
        }
        log.info("ingest end: documentId={}, format={}, status={}, total={}, accepted={}, rejected={}, replay={}",
                documentId, result.format(), result.status(), result.totalEntries(),
                result.accepted().size(), result.rejected().size(), result.idempotentReplay());
        return result;
    }

    private IngestResult doIngest(String documentId, SbomFormat format, SbomParser parser, JsonNode root) {
        List<ParsedEntry> entries = parser.extractEntries(root); // document failures thrown here
        List<IngestedComponent> accepted = new ArrayList<>();
        List<RejectedEntry> rejected = new ArrayList<>();
        java.util.Set<String> keysInDocument = new java.util.HashSet<>();

        for (ParsedEntry entry : entries) {
            NormalizationOutcome outcome = normalizer.normalize(entry, format);
            if (outcome instanceof NormalizationOutcome.Rejected r) {
                rejected.add(r.entry());
                continue;
            }
            Component component = ((NormalizationOutcome.Accepted) outcome).component();

            if (!keysInDocument.add(component.key())) {
                rejected.add(new RejectedEntry(entry.index(), component.name(), component.version(),
                        RejectReason.DUPLICATE_ENTRY,
                        "duplicate component within the same document: " + component.key()));
                continue;
            }
            ComponentStore.StoreOutcome storeOutcome = store.put(component, documentId);
            if (storeOutcome == ComponentStore.StoreOutcome.DUPLICATE) {
                // repeated submission: no new record, reported distinctly but not a failure
                accepted.add(new IngestedComponent(component.key(), component.name(),
                        component.version(), true, documentId));
            } else {
                accepted.add(new IngestedComponent(component.key(), component.name(),
                        component.version(), false, documentId));
            }
        }

        IngestStatus status = rejected.isEmpty()
                ? IngestStatus.ACCEPTED
                : accepted.isEmpty() ? IngestStatus.FAILED : IngestStatus.PARTIAL;
        return new IngestResult(documentId, format, status, false, entries.size(),
                List.copyOf(accepted), List.copyOf(rejected));
    }

    private JsonNode parseJson(String payload) {
        try {
            JsonNode root = objectMapper.readTree(payload);
            if (root == null || !root.isObject()) {
                throw new SbomIngestionException(RejectReason.MALFORMED_PAYLOAD,
                        "payload must be a JSON object");
            }
            return root;
        } catch (SbomIngestionException e) {
            throw e;
        } catch (Exception e) {
            throw new SbomIngestionException(RejectReason.MALFORMED_PAYLOAD,
                    "payload is not valid JSON: " + e.getMessage(), e);
        }
    }

    private static String resolveDocumentId(String clientDocId, String embeddedId, String payload) {
        if (clientDocId != null && !clientDocId.isBlank()) {
            return clientDocId.trim();
        }
        if (embeddedId != null && !embeddedId.isBlank()) {
            return embeddedId;
        }
        return "sha256:" + sha256(payload);
    }

    private static String sha256(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static IngestResult markReplay(IngestResult original) {
        return new IngestResult(original.documentId(), original.format(), original.status(),
                true, original.totalEntries(), original.accepted(), original.rejected());
    }

    public List<Component> listComponents() {
        return store.findAll();
    }

    public Optional<RiskAssessment> assessComponent(String key) {
        return store.findByKey(key).map(evaluator::assess);
    }
}
