package com.github.lisama569.sbomriskservicejava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.sbomriskservicejava.exception.SbomIngestionException;
import com.github.lisama569.sbomriskservicejava.ingest.ComponentStore;
import com.github.lisama569.sbomriskservicejava.ingest.CycloneDxParser;
import com.github.lisama569.sbomriskservicejava.ingest.IdempotencyGuard;
import com.github.lisama569.sbomriskservicejava.ingest.Normalizer;
import com.github.lisama569.sbomriskservicejava.ingest.SbomFormatDetector;
import com.github.lisama569.sbomriskservicejava.ingest.SbomIngestionService;
import com.github.lisama569.sbomriskservicejava.ingest.SpdxParser;
import com.github.lisama569.sbomriskservicejava.model.IngestResult;
import com.github.lisama569.sbomriskservicejava.model.IngestStatus;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.rule.RuleEvaluator;
import com.github.lisama569.sbomriskservicejava.rule.RuleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SbomIngestionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SbomIngestionServiceTest.class);

    private SbomIngestionService service;
    private ComponentStore store;
    private RuleRepository ruleRepository;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper();
        SbomFormatDetector detector = new SbomFormatDetector(List.of(new CycloneDxParser(), new SpdxParser()));
        Normalizer normalizer = new Normalizer();
        store = new ComponentStore();
        IdempotencyGuard guard = new IdempotencyGuard();
        ruleRepository = new RuleRepository();
        RuleEvaluator evaluator = new RuleEvaluator(ruleRepository);
        service = new SbomIngestionService(mapper, detector, normalizer, store, guard, evaluator);
    }

    private static String cdx(String serial, String components) {
        return "{\"bomFormat\":\"CycloneDX\",\"serialNumber\":\"" + serial
                + "\",\"components\":[" + components + "]}";
    }

    private static String component(String name, String version, String purl) {
        return "{\"type\":\"library\",\"name\":\"" + name + "\",\"version\":\"" + version + "\""
                + (purl != null ? ",\"purl\":\"" + purl + "\"" : "") + "}";
    }

    @Test
    void malformedJsonIsDocumentFailure() {
        SbomIngestionException ex = assertThrows(SbomIngestionException.class,
                () -> service.ingest("{not valid json", null));
        log.info("input summary: garbage payload -> reason={}", ex.reason());
        assertEquals(RejectReason.MALFORMED_PAYLOAD, ex.reason());
    }

    @Test
    void unsupportedFormatIsDistinguishableFromMalformed() {
        SbomIngestionException malformed = assertThrows(SbomIngestionException.class,
                () -> service.ingest("[]", null));
        assertEquals(RejectReason.MALFORMED_PAYLOAD, malformed.reason());

        SbomIngestionException unsupported = assertThrows(SbomIngestionException.class,
                () -> service.ingest("{\"foo\":\"bar\",\"components\":[]}", null));
        log.info("input summary: unknown format markers -> reason={}", unsupported.reason());
        assertEquals(RejectReason.UNSUPPORTED_FORMAT, unsupported.reason());
    }

    @Test
    void partialSuccessKeepsGoodEntriesAndDistinguishesReasons() {
        String payload = cdx("urn:uuid:partial",
                component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20") + ","
                        + component("bad-version", "nope", "pkg:npm/bad-version@nope") + ","
                        + component("no-version", "", null));
        IngestResult result = service.ingest(payload, null);
        log.info("input summary: 3 entries (1 good, invalid version, missing version) -> status={}, accepted={}, rejected={}",
                result.status(), result.accepted().size(),
                result.rejected().stream().map(r -> r.index() + ":" + r.reason()).toList());
        assertEquals(IngestStatus.PARTIAL, result.status());
        assertEquals(1, result.accepted().size());
        assertEquals(2, result.rejected().size());
        assertEquals(RejectReason.INVALID_VERSION, result.rejected().get(0).reason());
        assertEquals(RejectReason.MISSING_VERSION, result.rejected().get(1).reason());
        // the good entry survived the failures
        assertEquals(1, service.listComponents().size());
    }

    @Test
    void allEntriesFailedIsOverallFailedAndNothingStored() {
        String payload = cdx("urn:uuid:allbad",
                component("", "1.0.0", "pkg:npm/x@1.0.0") + ","
                        + component("y", "bad", null));
        IngestResult result = service.ingest(payload, null);
        log.info("input summary: all-bad document -> status={}, rejectedReasons={}",
                result.status(), result.rejected().stream().map(r -> r.reason()).toList());
        assertEquals(IngestStatus.FAILED, result.status());
        assertEquals(0, result.accepted().size());
        assertEquals(0, service.listComponents().size());
    }

    @Test
    void duplicateEntriesWithinOneDocumentAreRejectedNotStoredTwice() {
        String payload = cdx("urn:uuid:dup-in-doc",
                component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20") + ","
                        + component("lodash-alias", "4.17.20", "pkg:npm/lodash@4.17.20"));
        IngestResult result = service.ingest(payload, null);
        log.info("input summary: same purl twice in one document -> status={}, reasons={}",
                result.status(), result.rejected().stream().map(r -> r.reason()).toList());
        assertEquals(IngestStatus.PARTIAL, result.status());
        assertEquals(1, result.accepted().size());
        assertEquals(1, result.rejected().size());
        assertEquals(RejectReason.DUPLICATE_ENTRY, result.rejected().get(0).reason());
        assertEquals(1, service.listComponents().size());
    }

    @Test
    void repeatedSubmissionIsIdempotentAndMarksReplay() {
        String payload = cdx("urn:uuid:resubmit",
                component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"));
        IngestResult first = service.ingest(payload, null);
        IngestResult second = service.ingest(payload, null);
        log.info("input summary: same document twice -> first.replay={}, second.replay={}, stored={}",
                first.idempotentReplay(), second.idempotentReplay(), service.listComponents().size());
        assertFalse(first.idempotentReplay());
        assertTrue(second.idempotentReplay());
        assertEquals(IngestStatus.ACCEPTED, first.status());
        assertEquals(IngestStatus.ACCEPTED, second.status());
        assertEquals(1, service.listComponents().size());
        assertEquals(first.accepted().size(), second.accepted().size());
    }

    @Test
    void sameComponentInTwoDocumentsDoesNotDuplicateRecord() {
        String doc1 = cdx("urn:uuid:doc-a", component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"));
        String doc2 = cdx("urn:uuid:doc-b", component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"));
        IngestResult r1 = service.ingest(doc1, null);
        IngestResult r2 = service.ingest(doc2, null);
        log.info("input summary: same component in two documents -> r1.accepted={}, r2.accepted(duplicateFlag)={}, storeSize={}",
                r1.accepted().size(),
                r2.accepted().stream().map(a -> a.key() + ":dup=" + a.duplicate()).toList(),
                service.listComponents().size());
        assertFalse(r1.accepted().get(0).duplicate());
        assertTrue(r2.accepted().get(0).duplicate());
        assertEquals(1, service.listComponents().size());
    }

    @Test
    void concurrentSameDocumentSubmissionsAreSerializedAndIdempotent() throws Exception {
        String payload = cdx("urn:uuid:concurrent-same",
                component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"));
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger replays = new AtomicInteger();
        AtomicInteger firsts = new AtomicInteger();
        List<IngestResult> results = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    IngestResult r = service.ingest(payload, null);
                    results.add(r);
                    if (r.idempotentReplay()) {
                        replays.incrementAndGet();
                    } else {
                        firsts.incrementAndGet();
                    }
                } catch (Exception ignored) {
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("input summary: {} concurrent submissions of one document -> firsts={}, replays={}, storeSize={}",
                threads, firsts.get(), replays.get(), service.listComponents().size());
        assertEquals(threads, results.size());
        assertEquals(1, firsts.get());
        assertEquals(threads - 1, replays.get());
        assertEquals(1, service.listComponents().size());
    }

    @Test
    void concurrentDifferentDocumentsDoNotBlockEachOther() throws Exception {
        int threads = 6;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < threads; i++) {
            int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    String payload = cdx("urn:uuid:different-" + idx,
                            component("lib-" + idx, "1.0.0", "pkg:npm/lib-" + idx + "@1.0.0"));
                    IngestResult r = service.ingest(payload, null);
                    assertEquals(IngestStatus.ACCEPTED, r.status());
                } catch (Exception ignored) {
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("input summary: {} concurrent distinct documents -> storeSize={}",
                threads, service.listComponents().size());
        assertEquals(threads, service.listComponents().size());
    }
}
