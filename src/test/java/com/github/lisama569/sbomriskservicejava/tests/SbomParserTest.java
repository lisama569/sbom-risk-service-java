package com.github.lisama569.sbomriskservicejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.sbomriskservicejava.exception.SbomIngestionException;
import com.github.lisama569.sbomriskservicejava.ingest.CycloneDxParser;
import com.github.lisama569.sbomriskservicejava.ingest.ParsedEntry;
import com.github.lisama569.sbomriskservicejava.ingest.SbomFormatDetector;
import com.github.lisama569.sbomriskservicejava.ingest.SpdxParser;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SbomParserTest {

    private static final Logger log = LoggerFactory.getLogger(SbomParserTest.class);

    private final ObjectMapper mapper = new ObjectMapper();
    private final CycloneDxParser cdx = new CycloneDxParser();
    private final SpdxParser spdx = new SpdxParser();
    private final SbomFormatDetector detector =
            new SbomFormatDetector(List.of(cdx, spdx));

    private JsonNode json(String s) {
        try {
            return mapper.readTree(s);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void detectsCycloneDxBomFormat() {
        JsonNode root = json("""
                {"bomFormat":"CycloneDX","serialNumber":"urn:uuid:doc-1","components":[]}
                """);
        log.info("input summary: CycloneDX marker bomFormat=CycloneDX");
        assertEquals(SbomFormat.CYCLONEDX_JSON, detector.detect(root));
        assertEquals("urn:uuid:doc-1", cdx.extractDocumentId(root));
    }

    @Test
    void detectsSpdxVersion() {
        JsonNode root = json("""
                {"spdxVersion":"SPDX-2.3","documentNamespace":"urn:spdx:doc-2","packages":[]}
                """);
        log.info("input summary: SPDX marker spdxVersion=SPDX-2.3");
        assertEquals(SbomFormat.SPDX_JSON, detector.detect(root));
        assertEquals("urn:spdx:doc-2", spdx.extractDocumentId(root));
    }

    @Test
    void unknownDocumentMarkersAreUnknownNotGuessed() {
        JsonNode root = json("""
                {"someOtherFormat":true,"items":[]}
                """);
        log.info("input summary: document with no bomFormat/spdxVersion markers");
        assertEquals(SbomFormat.UNKNOWN, detector.detect(root));
    }

    @Test
    void parsesCycloneDxEntriesIncludingLicense() {
        JsonNode root = json("""
                {"bomFormat":"CycloneDX","components":[
                  {"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20",
                   "licenses":[{"license":{"id":"MIT"}}]}
                ]}
                """);
        List<ParsedEntry> entries = cdx.extractEntries(root);
        assertEquals(1, entries.size());
        ParsedEntry e = entries.get(0);
        log.info("input summary: cdx entry name={} version={} purl={} license={}",
                e.name(), e.version(), e.purl(), e.license());
        assertEquals("lodash", e.name());
        assertEquals("4.17.20", e.version());
        assertEquals("pkg:npm/lodash@4.17.20", e.purl());
        assertEquals("MIT", e.license());
    }

    @Test
    void parsesSpdxPurlExternalRefAndNoassertionValues() {
        JsonNode root = json("""
                {"spdxVersion":"SPDX-2.3","packages":[
                  {"name":"log4j-core","versionInfo":"2.14.1",
                   "licenseDeclared":"NOASSERTION",
                   "externalRefs":[
                     {"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
                      "referenceLocator":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}
                ]}
                """);
        List<ParsedEntry> entries = spdx.extractEntries(root);
        ParsedEntry e = entries.get(0);
        log.info("input summary: spdx entry name={} version={} ecosystem={} purl={} license={}",
                e.name(), e.version(), e.ecosystem(), e.purl(), e.license());
        assertEquals("log4j-core", e.name());
        assertEquals("2.14.1", e.version());
        assertEquals("maven", e.ecosystem());
        assertNull(e.license());
    }

    @Test
    void missingComponentsArrayIsDocumentFailureWithDistinguishableReason() {
        JsonNode root = json("""
                {"bomFormat":"CycloneDX","serialNumber":"urn:uuid:doc-3"}
                """);
        SbomIngestionException ex = assertThrows(SbomIngestionException.class,
                () -> cdx.extractEntries(root));
        log.info("input summary: CycloneDX without components -> reason={}", ex.reason());
        assertEquals(RejectReason.MISSING_COMPONENTS, ex.reason());
    }

    @Test
    void nonObjectEntriesArePreservedForPerEntryRejection() {
        JsonNode root = json("""
                {"bomFormat":"CycloneDX","components":[
                  "totally-not-an-object",
                  {"name":"ok","version":"1.0.0"}
                ]}
                """);
        List<ParsedEntry> entries = cdx.extractEntries(root);
        assertEquals(2, entries.size());
        assertNull(entries.get(0).name());
        assertEquals("ok", entries.get(1).name());
    }
}
