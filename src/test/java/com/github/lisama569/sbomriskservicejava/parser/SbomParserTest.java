package com.github.lisama569.sbomriskservicejava.parser;

import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 两种 SBOM 格式解析、归一化与逐条拒绝原因测试。 */
class SbomParserTest {

    private static final Logger log = LoggerFactory.getLogger(SbomParserTest.class);

    private final CycloneDxBomParser cdxParser = new CycloneDxBomParser();
    private final SpdxBomParser spdxParser = new SpdxBomParser();
    private final FormatDetector detector = new FormatDetector();

    private static final String CYCLONEDX_MIXED = """
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.5",
              "components": [
                {"type": "library", "name": "org.apache.logging.log4j:log4j-core",
                 "version": "2.14.0", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"},
                {"type": "library", "version": "1.0.0"},
                {"type": "library", "name": "lodash"},
                {"type": "library", "name": "bad", "version": "v1.0.0"}
              ]
            }
            """;

    private static final String SPDX_MIXED = """
            {
              "spdxVersion": "SPDX-2.3",
              "packages": [
                {"name": "lodash", "versionInfo": "4.17.20",
                 "externalRefs": [
                   {"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"}
                 ]},
                {"name": "org.springframework:spring-beans", "versionInfo": "5.3.16"}
              ]
            }
            """;

    @Test
    @DisplayName("CycloneDX：1 条有效，缺名/缺版本/非法版本各 1 条，拒绝原因可区分")
    void cycloneDxClassifiesRejectionReasons() {
        ParseResult r = cdxParser.parse(CYCLONEDX_MIXED);
        log.info("CycloneDX 输入摘要: 4 个组件（1 有效 / 缺名 / 缺版本 / 非法版本），"
                + "归一接受={}，拒绝={}", r.components().size(), r.rejected().size());
        assertEquals(1, r.components().size());
        assertEquals(3, r.rejected().size());
        // 下标 1：缺名；下标 2：缺版本；下标 3：非法版本（保留清单顺序）
        assertEquals(RejectReason.MISSING_COMPONENT_NAME, r.rejected().get(0).reason());
        assertEquals(1, r.rejected().get(0).index());
        assertEquals(RejectReason.MISSING_COMPONENT_VERSION, r.rejected().get(1).reason());
        assertEquals(2, r.rejected().get(1).index());
        assertEquals(RejectReason.MALFORMED_VERSION, r.rejected().get(2).reason());
        assertEquals(3, r.rejected().get(2).index());
        var first = r.components().get(0);
        assertEquals("maven", first.ecosystem());
        log.info("判定依据: 归一组件 key={}（生态来自 purl）", first.key());
    }

    @Test
    @DisplayName("SPDX：正常组件归一，生态由 purl 推断，无 purl 为 unknown")
    void spdxNormalizesPackagesAndEcosystem() {
        ParseResult r = spdxParser.parse(SPDX_MIXED);
        log.info("SPDX 输入摘要: 2 个 package，归一接受={}，拒绝={}",
                r.components().size(), r.rejected().size());
        assertEquals(2, r.components().size());
        assertEquals(0, r.rejected().size());
        assertEquals("npm", r.components().get(0).ecosystem());
        assertEquals("unknown", r.components().get(1).ecosystem());
    }

    @Test
    @DisplayName("格式识别：CycloneDX 与 SPDX 各自命中，未知文档抛异常")
    void formatDetection() {
        assertEquals(SbomFormat.CYCLONEDX_JSON, detector.detect(CYCLONEDX_MIXED));
        assertEquals(SbomFormat.SPDX_JSON, detector.detect(SPDX_MIXED));
        SbomParseException ex = assertThrows(SbomParseException.class,
                () -> detector.detect("{\"foo\":\"bar\"}"));
        log.warn("未知格式被拒绝: 依据: {}", ex.getMessage());
    }

    @Test
    @DisplayName("坐标身份归一：purl 与 名字+ecosystems 的等价写法得到同一组件键")
    void purlAndNameSpellingsNormalizeToSameIdentity() {
        String viaPurl = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"log4j-core","version":"2.14.0",
                   "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"}]}
                """;
        String viaName = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"org.apache.logging.log4j:log4j-core","version":"2.14.0",
                   "ecosystems":["maven"]}]}
                """;
        var a = cdxParser.parse(viaPurl).components().get(0);
        var b = cdxParser.parse(viaName).components().get(0);
        log.info("输入摘要: 同一库两种等价写法 | purl 写法键={} | 名字写法键={}", a.key(), b.key());
        assertEquals(b.key(), a.key());
        assertEquals("maven", a.ecosystem());
        assertEquals("org.apache.logging.log4j:log4j-core", a.name());
    }

    @Test
    @DisplayName("npm 作用域：purl %40 编码与名字字段 @scope 写法归一到同一身份")
    void npmScopeNormalizesAcrossSpellings() {
        String viaPurl = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"core","version":"15.0.0","purl":"pkg:npm/%40angular/core@15.0.0"}]}
                """;
        String viaName = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"@angular/core","version":"15.0.0","ecosystems":["npm"]}]}
                """;
        var a = cdxParser.parse(viaPurl).components().get(0);
        var b = cdxParser.parse(viaName).components().get(0);
        log.info("输入摘要: npm 作用域两种写法 | purl 键={} | 名字键={}", a.key(), b.key());
        assertEquals(b.key(), a.key());
    }

    @Test
    @DisplayName("条目版本缺失时回退坐标版本；不支持的坐标类型被明确拒绝且原因可区分")
    void versionFallsBackToPurlAndUnsupportedTypeRejected() {
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"lodash","purl":"pkg:npm/lodash@4.17.20"},
                  {"name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0"}
                ]}
                """;
        ParseResult r = cdxParser.parse(doc);
        log.info("输入摘要: 1 条版本取自 purl + 1 条 pypi 坐标 | 接受={} 拒绝={} 拒绝原因={}",
                r.components().size(), r.rejected().size(),
                r.rejected().stream().map(x -> x.reason().name()).toList());
        assertEquals(1, r.components().size());
        assertEquals("npm::lodash@4.17.20", r.components().get(0).key());
        assertEquals(1, r.rejected().size());
        assertEquals(RejectReason.UNSUPPORTED_PURL_TYPE, r.rejected().get(0).reason());
        assertEquals(1, r.rejected().get(0).index());
    }

    @Test
    @DisplayName("畸形 purl：回退字段法，生态取字段值，但身份被标记为不可靠（判定层强制 UNKNOWN）")
    void malformedPurlFallsBackToUnknownEcosystem() {
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"some-lib","version":"1.0.0","purl":"not-a-purl"}]}
                """;
        ParseResult r = cdxParser.parse(doc);
        log.info("输入摘要: 畸形 purl 条目 | 归一组件键={}", r.components().get(0).key());
        assertEquals(1, r.components().size());
        assertEquals("unknown", r.components().get(0).ecosystem());
    }

    @Test
    @DisplayName("畸形 purl 但标了 maven：组件照常入库，坐标身份标记为不可靠，不得当 CLEAN 放行")
    void malformedPurlLabeledMavenIsMarkedUnreliable() {
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"some-maven-lib","version":"1.0.0",
                   "purl":"not-a-purl","ecosystems":["maven"]}]}
                """;
        ParseResult r = cdxParser.parse(doc);
        log.info("输入摘要: 畸形 purl + ecosystems=[maven] | 组件键={} | 坐标备注={}",
                r.components().get(0).key(), r.components().get(0).coordinateNote());
        assertEquals(1, r.components().size());
        assertEquals("maven", r.components().get(0).ecosystem());
        org.junit.jupiter.api.Assertions.assertFalse(r.components().get(0).identityReliable());
        org.junit.jupiter.api.Assertions.assertTrue(
                r.components().get(0).coordinateNote().startsWith("malformed-purl:"));
    }

    @Test
    @DisplayName("Maven 斜杠名字写法（组名/构件名）归一到与规则库一致的 groupId:artifactId 身份")
    void mavenSlashNameSpellingNormalizesToRuleIdentity() {
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"org.apache.logging.log4j/log4j-core","version":"2.14.0",
                   "ecosystems":["maven"]}]}
                """;
        var c = cdxParser.parse(doc).components().get(0);
        log.info("输入摘要: 斜杠名字写法 | 判定依据: 归一身份={}", c.key());
        assertEquals("maven::org.apache.logging.log4j:log4j-core@2.14.0", c.key());
    }

    @Test
    @DisplayName("Maven 纯大小写不同的字段写法归一到同一身份（生态标签大小写同样归一）")
    void mavenUpperCaseFieldSpellingNormalizes() {
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"ORG.APACHE.LOGGING.LOG4J/LOG4J-CORE","version":"2.14.0",
                   "ecosystems":["MAVEN"]}]}
                """;
        var c = cdxParser.parse(doc).components().get(0);
        log.info("输入摘要: 全大写 maven 字段写法 | 判定依据: 归一身份={}", c.key());
        assertEquals("maven::org.apache.logging.log4j:log4j-core@2.14.0", c.key());
    }

    @Test
    @DisplayName("条目级拒绝与 UNKNOWN 条目一一对应：不支持坐标、缺名、缺版本、非法版本各一条")
    void rejectedItemsHavePairedUnresolvedEntries() {
        ParseResult r = cdxParser.parse(CYCLONEDX_MIXED);
        log.info("输入摘要: 混合清单 | rejected={} | unresolved={}",
                r.rejected().size(), r.unresolved().size());
        assertEquals(r.rejected().size(), r.unresolved().size());
        for (var u : r.unresolved()) {
            org.junit.jupiter.api.Assertions.assertTrue(u.reason().startsWith("UNKNOWN:"),
                    "unresolved entry must carry an UNKNOWN reason: " + u);
        }
        // 不支持坐标类型的用例（pypi）同样要带出一条 UNKNOWN
        String pypi = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0"}]}
                """;
        ParseResult r2 = cdxParser.parse(pypi);
        assertEquals(1, r2.rejected().size());
        assertEquals(1, r2.unresolved().size());
        assertEquals("pypi::requests@2.31.0", r2.unresolved().get(0).key());
        log.info("判定依据: pypi 条目 UNKNOWN 键={} 原因={}",
                r2.unresolved().get(0).key(), r2.unresolved().get(0).reason());
    }

    @Test
    @DisplayName("畸形文档分类：非法 JSON / 空内容 / 缺数组 / 数组类型错误 / 根非对象")
    void malformedDocumentsAreRejectedAtDocumentLevel() {
        assertDocumentFailure("not json at all", "非法 JSON");
        assertDocumentFailure("", "空内容");
        assertDocumentFailure("   ", "空白内容");
        assertDocumentFailure("{\"bomFormat\":\"CycloneDX\"}", "缺 components");
        assertDocumentFailure("{\"bomFormat\":\"CycloneDX\",\"components\":{}}", "components 非数组");
        assertDocumentFailure("{\"spdxVersion\":\"SPDX-2.3\"}", "缺 packages");
        assertDocumentFailure("[]", "根不是对象");
    }

    /** 无论失败发生在格式识别还是解析阶段，都应归类为 SbomParseException 文档级失败。 */
    private void assertDocumentFailure(String content, String label) {
        SbomParseException e = assertThrows(SbomParseException.class, () -> {
            SbomFormat f = detector.detect(content);
            SbomParser p = f == SbomFormat.CYCLONEDX_JSON ? cdxParser : spdxParser;
            p.parse(content);
        }, label);
        log.warn("畸形清单[{}]被归类为文档级失败 | 依据: {}", label, e.getMessage());
        assertTrue(!e.getMessage().isBlank());
    }
}
