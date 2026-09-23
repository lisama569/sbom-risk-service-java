package com.github.lisama569.sbomriskservicejava.tests;

import com.github.lisama569.sbomriskservicejava.ingest.NormalizationOutcome;
import com.github.lisama569.sbomriskservicejava.ingest.Normalizer;
import com.github.lisama569.sbomriskservicejava.ingest.ParsedEntry;
import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class NormalizerTest {

    private static final Logger log = LoggerFactory.getLogger(NormalizerTest.class);

    private final Normalizer normalizer = new Normalizer();

    private ParsedEntry entry(int index, String name, String version, String purl,
                              String ecosystem, String license) {
        return new ParsedEntry(index, name, version, purl, ecosystem, license);
    }

    private RejectReason reasonOf(String name, String version, String purl, String ecosystem) {
        ParsedEntry e = entry(0, name, version, purl, ecosystem, null);
        NormalizationOutcome outcome = normalizer.normalize(e, SbomFormat.CYCLONEDX_JSON);
        NormalizationOutcome.Rejected rejected = assertInstanceOf(NormalizationOutcome.Rejected.class, outcome);
        log.info("input summary: name={} version={} purl={} ecosystem={} -> rejected reason={} detail={}",
                name, version, purl, ecosystem, rejected.entry().reason(), rejected.entry().detail());
        return rejected.entry().reason();
    }

    @Test
    void missingNameVersionAndInvalidVersionAreDistinguishable() {
        assertEquals(RejectReason.MISSING_NAME, reasonOf(null, "1.0.0", null, "npm"));
        assertEquals(RejectReason.MISSING_VERSION, reasonOf("lib", "  ", null, "npm"));
        assertEquals(RejectReason.INVALID_VERSION, reasonOf("lib", "not-a-version", null, "npm"));
        assertEquals(RejectReason.INVALID_VERSION, reasonOf("lib", "01.2.3", null, "npm"));
    }

    @Test
    void malformedPurlIsMissingIdentifier() {
        assertEquals(RejectReason.MISSING_IDENTIFIER,
                reasonOf("lib", "1.0.0", "http://not-a-purl", null));
        assertEquals(RejectReason.MISSING_IDENTIFIER,
                reasonOf("lib", "1.0.0", "pkg:", null));
    }

    @Test
    void missingEcosystemAndPurlIsMissingIdentifier() {
        assertEquals(RejectReason.MISSING_IDENTIFIER,
                reasonOf("lib", "1.0.0", null, null));
    }

    @Test
    void purlDefinesStableKeyAndEcosystem() {
        ParsedEntry e = entry(0, "ignored-different-name?", "2.14.1",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", null, "Apache-2.0");
        NormalizationOutcome outcome = normalizer.normalize(e, SbomFormat.SPDX_JSON);
        Component c = ((NormalizationOutcome.Accepted) outcome).component();
        log.info("input summary: maven purl -> key={} ecosystem={}", c.key(), c.ecosystem());
        assertEquals("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", c.key());
        assertEquals("maven", c.ecosystem());
        assertEquals("2.14.1", c.version());
    }

    @Test
    void syntheticKeyWhenNoPurlButEcosystemPresent() {
        ParsedEntry e = entry(0, "left-pad", "1.0.0", null, "NPM", null);
        Component c = ((NormalizationOutcome.Accepted) normalizer
                .normalize(e, SbomFormat.CYCLONEDX_JSON)).component();
        log.info("input summary: ecosystem only -> key={}", c.key());
        assertEquals("pkg:npm/left-pad@1.0.0", c.key());
        assertEquals("npm", c.ecosystem());
    }

    @Test
    void looseDottedNumericVersionIsAccepted() {
        Component c = ((NormalizationOutcome.Accepted) normalizer.normalize(
                entry(0, "durable", "1.2", null, "maven", null),
                SbomFormat.CYCLONEDX_JSON)).component();
        log.info("input summary: loose version accepted key={} version={}", c.key(), c.version());
        assertEquals("1.2", c.version());
    }
}
