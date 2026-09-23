package com.github.lisama569.sbomriskservicejava.tests;

import com.github.lisama569.sbomriskservicejava.version.ComparisonOutcome;
import com.github.lisama569.sbomriskservicejava.version.ParseResult;
import com.github.lisama569.sbomriskservicejava.version.Version;
import com.github.lisama569.sbomriskservicejava.version.VersionCompare;
import com.github.lisama569.sbomriskservicejava.version.VersionParser;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VersionCompareTest {

    private static final Logger log = LoggerFactory.getLogger(VersionCompareTest.class);

    private Version semver(String s) {
        ParseResult r = VersionParser.parseSemver(s);
        assertInstanceOf(ParseResult.Ok.class, r, () -> "parse error for " + s);
        return ((ParseResult.Ok) r).value();
    }

    private Version lenient(String s) {
        ParseResult r = VersionParser.parseLenient(s);
        assertInstanceOf(ParseResult.Ok.class, r, () -> "parse error for " + s);
        return ((ParseResult.Ok) r).value();
    }

    private void assertCmp(String expected, String a, String b) {
        ComparisonOutcome actual = VersionCompare.compare(semver(a), semver(b));
        log.info("input: compare('{}','{}') -> {}", a, b, actual);
        assertEquals(ComparisonOutcome.valueOf(expected), actual);
    }

    @Test
    void semverCoreOrdering() {
        assertCmp("LOWER", "1.2.3", "1.2.4");
        assertCmp("LOWER", "1.2.3", "1.3.0");
        assertCmp("LOWER", "1.2.3", "2.0.0");
        assertCmp("EQUAL", "1.2.3", "1.2.3");
        assertCmp("GREATER", "2.0.0", "1.9.9");
    }

    @Test
    void semverPrereleaseIsLowerThanRelease() {
        assertCmp("LOWER", "1.0.0-alpha", "1.0.0");
        assertCmp("LOWER", "1.0.0-alpha.2", "1.0.0-alpha.10"); // numeric identifier 2 < 10
        assertCmp("LOWER", "1.0.0-alpha", "1.0.0-beta");
        assertCmp("GREATER", "1.0.0-rc.1", "1.0.0-beta.11");
    }

    @Test
    void leadingVPrefixAccepted() {
        assertEquals(ComparisonOutcome.EQUAL,
                VersionCompare.compare(semver("v1.2.3"), semver("1.2.3")));
    }

    @Test
    void looseVersionZeroPaddedEqualsRelease() {
        log.info("input: compare loose '1.2' vs semver '1.2.0'");
        assertEquals(ComparisonOutcome.EQUAL,
                VersionCompare.compare(lenient("1.2"), semver("1.2.0")));
        log.info("input: compare loose '1.2' vs semver '1.2.0-alpha'");
        assertEquals(ComparisonOutcome.GREATER,
                VersionCompare.compare(lenient("1.2"), semver("1.2.0-alpha")));
    }

    @Test
    void rejectsNonSemverForStrictParse() {
        String[] invalid = {"", "1.2", "01.2.3", "1.2", "banana", "1.2.3.4", "1.x.0"};
        for (String s : invalid) {
            log.info("input: strict parse '{}'", s);
            assertInstanceOf(ParseResult.Error.class, VersionParser.parseSemver(s),
                    "expected strict parse failure for '" + s + "'");
        }
        assertTrue(true);
    }

    @Test
    void lenientAcceptsOnlySemverOrDottedNumeric() {
        assertInstanceOf(ParseResult.Ok.class, VersionParser.parseLenient("4.11.3.2024"));
        assertInstanceOf(ParseResult.Error.class, VersionParser.parseLenient("1.2-rc1"));
        assertInstanceOf(ParseResult.Error.class, VersionParser.parseLenient("not-a-version"));
    }
}
