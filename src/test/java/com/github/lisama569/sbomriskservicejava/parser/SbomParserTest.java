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
