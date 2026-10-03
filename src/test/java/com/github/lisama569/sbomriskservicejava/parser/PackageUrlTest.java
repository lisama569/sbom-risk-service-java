package com.github.lisama569.sbomriskservicejava.parser;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** purl 包坐标解析：maven/npm 规范身份、不支持类型、畸形坐标分类。 */
class PackageUrlTest {

    private static final Logger log = LoggerFactory.getLogger(PackageUrlTest.class);

    private static void logResult(String input, PackageUrl.Result r) {
        log.info("purl 输入摘要: {} | 解析: status={}, ecosystem={}, name={}, detail={}",
                input, r.status(), r.ecosystem(), r.canonicalName(), r.detail());
    }

    @Test
    @DisplayName("maven 坐标：group/artifact 归一为 group:artifact 并小写，版本/qualifiers/subpath 不影响身份")
    void mavenCoordinatesNormalize() {
        PackageUrl.Result r1 = PackageUrl.parse(
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0");
        logResult("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0", r1);
        assertEquals(PackageUrl.Status.OK, r1.status());
        assertEquals("maven", r1.ecosystem());
        assertEquals("org.apache.logging.log4j:log4j-core", r1.canonicalName());

        PackageUrl.Result r2 = PackageUrl.parse(
                "pkg:maven/Org.Example/Lib@1.0.0?type=jar#classes");
        logResult("pkg:maven/Org.Example/Lib@1.0.0?type=jar#classes", r2);
        assertEquals(PackageUrl.Status.OK, r2.status());
        assertEquals("org.example:lib", r2.canonicalName());
    }

    @Test
    @DisplayName("npm 坐标：普通名与 %40 作用域名各自归一，大小写归一")
    void npmCoordinatesNormalize() {
        PackageUrl.Result plain = PackageUrl.parse("pkg:npm/lodash@4.17.20");
        logResult("pkg:npm/lodash@4.17.20", plain);
        assertEquals(PackageUrl.Status.OK, plain.status());
        assertEquals("npm", plain.ecosystem());
        assertEquals("lodash", plain.canonicalName());

        PackageUrl.Result scoped = PackageUrl.parse("pkg:npm/%40Angular/Core@15.0.0");
        logResult("pkg:npm/%40Angular/Core@15.0.0", scoped);
        assertEquals(PackageUrl.Status.OK, scoped.status());
        assertEquals("@angular/core", scoped.canonicalName());
    }

    @Test
    @DisplayName("不支持的坐标类型：结构合法时给出 UNSUPPORTED_TYPE 与通用身份，不混为普通名字")
    void unsupportedTypeIsDistinguishable() {
        PackageUrl.Result r = PackageUrl.parse("pkg:deb/debian/libssl3@3.0.0");
        logResult("pkg:deb/debian/libssl3@3.0.0", r);
        assertEquals(PackageUrl.Status.UNSUPPORTED_TYPE, r.status());
        assertEquals("deb", r.ecosystem());
        assertEquals("debian/libssl3", r.canonicalName());
        assertTrue(r.detail().contains("deb"));
    }

    @Test
    @DisplayName("畸形坐标：缺 pkg: 前缀 / 缺路径 / maven 缺组名 / npm 段数非法 / 空白，均为 MALFORMED")
    void malformedCoordinatesAreDistinguishable() {
        String[] bad = {
                null,
                "   ",
                "not-a-purl",
                "pkg:",
                "pkg:maven",
                "pkg:maven/onlyartifact@1.0.0",
                "pkg:maven/a/b/c@1.0.0",
                "pkg:npm/a/b/c@1.0.0",
                "pkg:npm/plainscope/pkg@1.0.0"
        };
        for (String p : bad) {
            PackageUrl.Result r = PackageUrl.parse(p);
            logResult(String.valueOf(p), r);
            assertEquals(PackageUrl.Status.MALFORMED, r.status(), "input=" + p);
        }
    }
}
