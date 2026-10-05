package com.github.lisama569.sbomriskservicejava.parser;

import com.github.lisama569.sbomriskservicejava.parser.PurlParser.Malformed;
import com.github.lisama569.sbomriskservicejava.parser.PurlParser.Resolved;
import com.github.lisama569.sbomriskservicejava.parser.PurlParser.Result;
import com.github.lisama569.sbomriskservicejava.parser.PurlParser.Unsupported;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

/** 包坐标（purl）解析：maven/npm 归一、等价写法、不支持类型与畸形坐标。 */
class PurlParserTest {

    private static final Logger log = LoggerFactory.getLogger(PurlParserTest.class);

    private static PackageCoordinate resolved(String purl) {
        Result r = PurlParser.parse(purl);
        log.info("输入摘要: purl={} | 判定: {}", purl, r);
        return assertInstanceOf(Resolved.class, r, "expected Resolved but got " + r).coordinate();
    }

    @Test
    @DisplayName("maven 坐标：组名+构件名归一为 groupId:artifactId，版本可提取")
    void mavenCoordinates() {
        PackageCoordinate c = resolved("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0");
        assertEquals("maven", c.ecosystem());
        assertEquals("org.apache.logging.log4j:log4j-core", c.name());
        assertEquals("2.14.0", c.version());
    }

    @Test
    @DisplayName("maven 等价写法：scheme 大写、带 qualifiers/subpath 归一到同一身份")
    void mavenEquivalentSpellings() {
        PackageCoordinate a = resolved("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0");
        PackageCoordinate b = resolved("PKG:MAVEN/org.apache.logging.log4j/log4j-core@2.14.0?type=jar#sub");
        assertEquals(a.ecosystem(), b.ecosystem());
        assertEquals(a.name(), b.name());
        assertEquals(a.version(), b.version());
        log.info("判定依据: 等价写法归一 => {}::{}@{}", b.ecosystem(), b.name(), b.version());
    }

    @Test
    @DisplayName("npm 作用域坐标：%40 编码与裸 @ 等价，名称小写归一")
    void npmScopedCoordinates() {
        PackageCoordinate a = resolved("pkg:npm/%40angular/core@15.0.0");
        PackageCoordinate b = resolved("pkg:npm/@angular/core@15.0.0");
        assertEquals("npm", a.ecosystem());
        assertEquals("@angular/core", a.name());
        assertEquals("15.0.0", a.version());
        assertEquals(a.name(), b.name());
        PackageCoordinate upper = resolved("pkg:npm/%40Angular/Core@15.0.0");
        assertEquals("@angular/core", upper.name());
        log.info("判定依据: 作用域等价写法归一 => {}", a.name());
    }

    @Test
    @DisplayName("npm 无作用域坐标与无版本坐标")
    void npmUnscopedAndVersionless() {
        PackageCoordinate c = resolved("pkg:npm/lodash@4.17.20");
        assertEquals("lodash", c.name());
        PackageCoordinate noVersion = resolved("pkg:npm/lodash");
        assertEquals("lodash", noVersion.name());
        assertNull(noVersion.version());
    }

    @Test
    @DisplayName("跨生态隔离：同名坐标在 maven 与 npm 下得到不同身份")
    void crossEcosystemIsolation() {
        PackageCoordinate m = resolved("pkg:maven/lodash/lodash@4.17.20");
        PackageCoordinate n = resolved("pkg:npm/lodash@4.17.20");
        log.info("输入摘要: 同名 lodash 两种生态 | maven 身份={} | npm 身份={}", m.name(), n.name());
        assertEquals("lodash:lodash", m.name());
        assertEquals("lodash", n.name());
        assertEquals("maven", m.ecosystem());
        assertEquals("npm", n.ecosystem());
    }

    @Test
    @DisplayName("maven 大小写不敏感：坐标仅大小写不同也归一到同一稳定身份")
    void mavenCoordinatesAreCaseInsensitive() {
        PackageCoordinate lower = resolved("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0");
        PackageCoordinate upper = resolved("pkg:maven/ORG.APACHE.LOGGING.LOG4J/LOG4J-CORE@2.14.0");
        assertEquals(lower.ecosystem(), upper.ecosystem());
        assertEquals(lower.name(), upper.name());
        assertEquals("org.apache.logging.log4j:log4j-core", upper.name());
        log.info("判定依据: 大小写不同的 maven 坐标归一 => {}", upper.name());
    }

    @Test
    @DisplayName("不支持的坐标类型：明确返回 Unsupported 且携带类型，绝不解析成普通名字")
    void unsupportedTypeIsDistinguishable() {
        Result r = PurlParser.parse("pkg:pypi/requests@2.31.0");
        log.info("输入摘要: purl=pkg:pypi/requests@2.31.0 | 判定: {}", r);
        Unsupported u = assertInstanceOf(Unsupported.class, r);
        assertEquals("pypi", u.type());
        // 原始名称与版本随拒绝结果带出，供报告以 UNKNOWN 条目展示，绝不丢失
        assertEquals("requests", u.rawName());
        assertEquals("2.31.0", u.version());
    }

    @Test
    @DisplayName("畸形坐标：缺 scheme / 缺名称段 / maven 缺 groupId / 空名称，均返回 Malformed")
    void malformedCoordinates() {
        assertInstanceOf(Malformed.class, logAndParse("maven/org.apache/logging@1.0.0"));
        assertInstanceOf(Malformed.class, logAndParse("pkg:maven"));
        assertInstanceOf(Malformed.class, logAndParse("pkg:maven/log4j-core@2.14.0"));
        assertInstanceOf(Malformed.class, logAndParse("pkg:npm/@1.0.0"));
    }

    private static Result logAndParse(String purl) {
        Result r = PurlParser.parse(purl);
        log.info("输入摘要: purl={} | 判定: {}", purl, r);
        return r;
    }
}
