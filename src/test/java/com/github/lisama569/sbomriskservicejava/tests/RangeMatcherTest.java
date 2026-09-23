package com.github.lisama569.sbomriskservicejava.tests;

import com.github.lisama569.sbomriskservicejava.exception.RuleConfigurationException;
import com.github.lisama569.sbomriskservicejava.version.ParseResult;
import com.github.lisama569.sbomriskservicejava.version.RangeExpression;
import com.github.lisama569.sbomriskservicejava.version.RangeMatcher;
import com.github.lisama569.sbomriskservicejava.version.Version;
import com.github.lisama569.sbomriskservicejava.version.VersionParser;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RangeMatcherTest {

    private static final Logger log = LoggerFactory.getLogger(RangeMatcherTest.class);

    private Version v(String s) {
        ParseResult r = VersionParser.parseLenient(s);
        assert r instanceof ParseResult.Ok : s;
        return ((ParseResult.Ok) r).value();
    }

    private Boolean match(String range, String version) {
        RangeExpression parsed = RangeMatcher.parse(range);
        Boolean result = RangeMatcher.matches(parsed, v(version));
        log.info("input: version '{}' in range '{}' -> {}", version, range, result);
        return result;
    }

    @Test
    void comparisonConjunction() {
        String range = ">=4.0.0 <4.17.21";
        assertTrue(match(range, "4.0.0"));
        assertTrue(match(range, "4.17.20"));
        assertFalse(match(range, "4.17.21"));
        assertFalse(match(range, "3.9.9"));
    }

    @Test
    void disjunction() {
        String range = "<0.2.1 || >1.0.0 <1.2.6";
        assertTrue(match(range, "0.2.0"));
        assertTrue(match(range, "1.2.5"));
        assertFalse(match(range, "1.0.0"));
        assertFalse(match(range, "1.2.6"));
    }

    @Test
    void wildcardRanges() {
        assertTrue(match("*", "9.9.9"));
        assertTrue(match("1.*", "1.5.0"));
        assertFalse(match("1.*", "2.0.0"));
        assertTrue(match("1.2.*", "1.2.9"));
        assertFalse(match("1.2.*", "1.3.0"));
        // pre-release is not covered by a numeric prefix wildcard
        assertFalse(match("1.*", "1.0.0-alpha"));
    }

    @Test
    void exactAndTildeAndCaret() {
        assertTrue(match("2.5.0", "2.5.0"));
        assertFalse(match("2.5.0", "2.5.1"));
        assertTrue(match("~2.5.0", "2.5.9"));
        assertFalse(match("~2.5.0", "2.6.0"));
        assertTrue(match("^1.2.3", "1.9.0"));
        assertFalse(match("^1.2.3", "2.0.0"));
        assertTrue(match("^0.2.3", "0.2.9"));
        assertFalse(match("^0.2.3", "0.3.0"));
        assertTrue(match("^0.0.3", "0.0.3"));
        assertFalse(match("^0.0.3", "0.0.4"));
    }

    @Test
    void looseVersionMatchesComparableBounds() {
        // "4.17" zero-pads to 4.17.0, decidable
        assertTrue(match(">=4.0.0 <4.17.21", "4.17"));
        assertFalse(match(">=4.17.21", "4.17"));
    }

    @Test
    void invalidRangesAreRejectedNotSilentlyKept() {
        String[] invalid = {">>", ">=banana", "1.2.3.4", "~1.2", "1.2.3.*", "  ", "<"};
        for (String range : invalid) {
            log.info("input: parse invalid range '{}'", range);
            assertThrows(RuleConfigurationException.class, () -> RangeMatcher.parse(range),
                    "expected rejection for range '" + range + "'");
        }
    }

    @Test
    void notEqualOperatorIsAlwaysDecidable() {
        RangeExpression ne = RangeMatcher.parse("!=1.2.3");
        assertTrue(RangeMatcher.matches(ne, v("4.5.6")));
        assertFalse(RangeMatcher.matches(ne, v("1.2.3")));
    }

    @Test
    void commaSeparatedConjunctionSupported() {
        assertTrue(match(">=1.0.0,<2.0.0", "1.5.0"));
        assertFalse(match(">=1.0.0,<2.0.0", "2.0.0"));
    }
}
