package com.github.lisama569.sbomriskservicejava.version;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 语义化版本解析与比较：含输入摘要与比较依据日志。 */
class SemVerTest {

    private static final Logger log = LoggerFactory.getLogger(SemVerTest.class);

    @ParameterizedTest(name = "[{index}] {0} 应可解析")
    @ValueSource(strings = {"1.2.3", "0.0.0", "10.20.30", "1.2.3-alpha", "1.2.3-alpha.1",
            "1.0.0-rc.1+build.5", "1.2.3+sha.abc"})
    void validVersionsParse(String raw) {
        SemVer v = SemVer.parse(raw);
        log.info("解析输入摘要: version='{}' => major={}, minor={}, patch={}, prerelease={}",
                raw, v.major(), v.minor(), v.patch(), v.isPrerelease());
        assertEquals(raw, v.raw());
    }

    @ParameterizedTest(name = "[{index}] 非法版本 [{0}] 必须抛 VersionParseException")
    @ValueSource(strings = {"", "   ", "1", "1.2", "1.2.3.4", "v1.2.3", "1.2.x", "01.2.3",
            "1.02.3", "1.2.3-", "1.2.3-01", "1.2.3-alpha..1", "not-a-version"})
    void invalidVersionsRejected(String raw) {
        VersionParseException ex = assertThrows(VersionParseException.class, () -> SemVer.parse(raw));
        log.warn("非法版本被拒绝: input='{}' | 依据: {}", raw, ex.getMessage());
    }

    @ParameterizedTest(name = "[{index}] {0} 与 {1} 比较 => {2}")
    @CsvSource(delimiter = '|', textBlock = """
            1.2.3        | 1.2.4         | -1
            1.2.3        | 1.3.0         | -1
            1.2.3        | 2.0.0         | -1
            2.0.0        | 1.99.99       | 1
            1.0.0-alpha  | 1.0.0         | -1
            1.0.0-alpha  | 1.0.0-alpha.1 | -1
            1.0.0-alpha.1| 1.0.0-beta    | -1
            1.0.0-1      | 1.0.0-2       | -1
            1.0.0-beta   | 1.0.0-11      | 1
            1.0.0+build1 | 1.0.0+build2  | 0
            """)
    void orderingFollowsSemVer(String a, String b, int expectedSign) {
        SemVer x = SemVer.parse(a.trim());
        SemVer y = SemVer.parse(b.trim());
        int cmp = Integer.compare(x.compareTo(y), 0);
        log.info("版本比较依据: compare('{}','{}') = {}", a, b, cmp);
        assertEquals(expectedSign, cmp);
    }

    @Test
    @DisplayName("预发布小于正式版，数字标识小于字符串标识")
    void prereleaseSpecifics() {
        assertTrue(SemVer.parse("1.0.0-alpha").compareTo(SemVer.parse("1.0.0")) < 0);
        assertTrue(SemVer.parse("1.0.0-1").compareTo(SemVer.parse("1.0.0-alpha")) < 0);
        assertTrue(SemVer.parse("1.0.0-alpha").compareTo(SemVer.parse("1.0.0-alpha")) == 0);
        log.info("预发布语义校验通过：alpha < release, 数字标识 < 字符串标识");
    }
}
