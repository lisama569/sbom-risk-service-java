package com.github.lisama569.sbomriskservicejava.version;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 版本范围（操作符/caret/tilde/通配符/区间）判定测试。 */
class VersionRangeTest {

    private static final Logger log = LoggerFactory.getLogger(VersionRangeTest.class);

    private boolean check(String expr, String version) {
        boolean hit = VersionRange.compile(expr).contains(SemVer.parse(version));
        log.info("范围判定依据: range='{}' contains version='{}' => {}", expr, version, hit);
        return hit;
    }

    @ParameterizedTest(name = "[{index}] {2}: {0} ~ {1}")
    @CsvSource(delimiter = '|', textBlock = """
            >=1.0.0        | 1.0.0          | true
            >=1.0.0        | 0.9.9          | false
            <2.0.0         | 2.0.0          | false
            <2.0.0         | 1.9.9          | true
            =1.2.3         | 1.2.3          | true
            =1.2.3         | 1.2.4          | false
            ^1.2.3         | 1.9.9          | true
            ^1.2.3         | 2.0.0          | false
            ^0.2.3         | 0.2.9          | true
            ^0.2.3         | 0.3.0          | false
            ^0.0.3         | 0.0.3          | true
            ^0.0.3         | 0.0.4          | false
            ~1.2.3         | 1.2.9          | true
            ~1.2.3         | 1.3.0          | false
            ~1             | 1.5.0          | true
            ~1             | 2.0.0          | false
            1.x            | 1.0.0          | true
            1.x            | 2.0.0          | false
            1.2.*          | 1.2.10         | true
            1.2.*          | 1.3.0          | false
            *              | 9.9.9          | true
            [1.0.0,2.0.0)  | 1.0.0          | true
            [1.0.0,2.0.0)  | 2.0.0          | false
            (1.0.0,2.0.0]  | 1.0.0          | false
            (1.0.0,2.0.0]  | 2.0.0          | true
            >=1.0.0,<2.0.0 | 1.5.0          | true
            >=1.0.0,<2.0.0 | 2.0.0          | false
            [2.0.0,2.12.3) | 2.12.2         | true
            [2.0.0,2.12.3) | 2.12.3         | false
            """)
    void rangeMembership(String expr, String version, boolean expected) {
        if (expected) {
            assertTrue(check(expr.trim(), version.trim()));
        } else {
            assertFalse(check(expr.trim(), version.trim()));
        }
    }

    @Test
    void caretKeepsPrereleaseSemanticsAtLowerBound() {
        // >=1.2.3 的下界包含预发布比较：1.2.3-rc1 < 1.2.3 不命中
        assertFalse(check("^1.2.3", "1.2.3-rc.1"));
        assertTrue(check("^1.2.3", "1.2.4-beta.1"));
    }

    @Test
    void orRangesCompileSeparatelyAndMatchAny() {
        var ranges = VersionRange.compileAny(java.util.List.of("[2.0.0,2.12.3)", "[2.13.0,2.15.0)"));
        SemVer v = SemVer.parse("2.14.0");
        boolean any = ranges.stream().anyMatch(r -> r.contains(v));
        log.info("OR 范围判定依据: log4j 风格区间 contains 2.14.0 => {}", any);
        assertTrue(any);
        assertFalse(ranges.stream().anyMatch(r -> r.contains(SemVer.parse("2.12.3"))));
        assertFalse(ranges.stream().anyMatch(r -> r.contains(SemVer.parse("2.16.0"))));
    }

    @ParameterizedTest(name = "[{index}] 非法区间 [{0}] 必须抛 VersionRangeException")
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "", "   ", "[1.0.0]", "(1.0.0,2.0.0", "1.0.0,2.0.0)", "[2.0.0,1.0.0]",
            ">=notaversion", "1.2", "^1.2.3.4", "1.*.2", "[1.0.0,1.0.0]"
    })
    void illegalRangesRejected(String expr) {
        VersionRangeException ex = assertThrows(VersionRangeException.class,
                () -> VersionRange.compile(expr));
        log.warn("非法区间被拒绝: input='{}' | 依据: {}", expr, ex.getMessage());
    }
}
