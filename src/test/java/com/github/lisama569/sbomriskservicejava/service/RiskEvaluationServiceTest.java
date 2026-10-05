package com.github.lisama569.sbomriskservicejava.service;

import com.github.lisama569.sbomriskservicejava.model.ComponentRisk;
import com.github.lisama569.sbomriskservicejava.model.PolicyRule;
import com.github.lisama569.sbomriskservicejava.model.RiskLevel;
import com.github.lisama569.sbomriskservicejava.model.RiskReport;
import com.github.lisama569.sbomriskservicejava.model.VulnerabilityRule;
import com.github.lisama569.sbomriskservicejava.parser.CycloneDxBomParser;
import com.github.lisama569.sbomriskservicejava.parser.FormatDetector;
import com.github.lisama569.sbomriskservicejava.parser.SbomParser;
import com.github.lisama569.sbomriskservicejava.parser.SpdxBomParser;
import com.github.lisama569.sbomriskservicejava.rules.RuleRepository;
import com.github.lisama569.sbomriskservicejava.version.VersionRangeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 风险判定：等级归类、边界、UNKNOWN 兜底、结论复现与规则更新。 */
class RiskEvaluationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(RiskEvaluationServiceTest.class);

    private ComponentRepository components;
    private RuleRepository rules;
    private SbomIngestService ingest;
    private RiskEvaluationService risk;

    private static String doc(String... triples) {
        StringBuilder sb = new StringBuilder("{\"bomFormat\":\"CycloneDX\",\"components\":[");
        for (int i = 0; i < triples.length; i += 3) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"name\":\"").append(triples[i]).append("\",\"version\":\"")
                    .append(triples[i + 1]).append("\",\"ecosystems\":[\"")
                    .append(triples[i + 2]).append("\"]}");
        }
        return sb.append("]}").toString();
    }

    private static String docUnknownEco(String... pairs) {
        StringBuilder sb = new StringBuilder("{\"bomFormat\":\"CycloneDX\",\"components\":[");
        for (int i = 0; i < pairs.length; i += 2) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"name\":\"").append(pairs[i]).append("\",\"version\":\"")
                    .append(pairs[i + 1]).append("\"}");
        }
        return sb.append("]}").toString();
    }

    @BeforeEach
    void setUp() {
        components = new ComponentRepository();
        rules = new RuleRepository();
        rules.loadDefaults();
        List<SbomParser> parsers = List.of(new CycloneDxBomParser(), new SpdxBomParser());
        ingest = new SbomIngestService(components, new FormatDetector(), parsers);
        risk = new RiskEvaluationService(components, rules);
    }

    private ComponentRisk find(RiskReport report, String nameFragment) {
        return report.components().stream()
                .filter(c -> c.component().contains(nameFragment))
                .findFirst().orElseThrow();
    }

    @Test
    @DisplayName("漏洞命中：log4j-core 2.14.0 落在 CVE-2021-44228 区间 => VULNERABLE；2.20.0 => CLEAN")
    void vulnerabilityRangeBoundaries() {
        ingest.ingest("t1", doc(
                "org.apache.logging.log4j:log4j-core", "2.14.0", "maven",
                "org.apache.logging.log4j:log4j-core", "2.20.0", "maven",
                "org.apache.logging.log4j:log4j-core", "2.12.3", "maven"));
        RiskReport report = risk.evaluate("t1");
        log.info("输入摘要: log4j-core 2.14.0 / 2.20.0 / 2.12.3（开闭区间边界）");
        assertEquals(RiskLevel.VULNERABLE, find(report, "log4j-core@2.14.0").level());
        assertEquals(RiskLevel.CLEAN, find(report, "log4j-core@2.20.0").level());
        // 2.12.3 是 [2.0.0,2.12.3) 的开区间上界，不命中
        assertEquals(RiskLevel.CLEAN, find(report, "log4j-core@2.12.3").level());
        report.components().forEach(c -> log.info("判定依据: {} => {} ({})",
                c.component(), c.level(), c.reasons()));
    }

    @Test
    @DisplayName("策略拒绝优先于漏洞：全版本封禁组件 => DENIED")
    void deniedTakesPrecedence() {
        ingest.ingest("t2", doc("com.legacy:deprecated-lib", "9.9.9", "maven"));
        RiskReport report = risk.evaluate("t2");
        ComponentRisk cr = report.components().get(0);
        log.info("输入摘要: 全版本封禁组件 | 判定: {} | 依据: {}", cr.level(), cr.reasons());
        assertEquals(RiskLevel.DENIED, cr.level());
        assertEquals(RiskLevel.DENIED, report.overallLevel());
    }

    @Test
    @DisplayName("无规则组件为 CLEAN 且有明确依据，而非缺省（前提：生态可判定）")
    void cleanHasExplicitReason() {
        ingest.ingest("t3", doc("com.example:totally-unknown-lib", "1.0.0", "maven"));
        ComponentRisk cr = risk.evaluate("t3").components().get(0);
        log.info("输入摘要: maven 生态但无任何规则匹配的组件 | 判定: {} | 依据: {}", cr.level(), cr.reasons());
        assertEquals(RiskLevel.CLEAN, cr.level());
        assertEquals("CLEAN:no-rules-matched", cr.reasons().get(0));
    }

    @Test
    @DisplayName("生态无法识别的组件不归为安全：结论 UNKNOWN 且总体等级随之抬升")
    void unrecognizedEcosystemYieldsUnknownNotClean() {
        // 一个可判定且无规则命中的 maven 组件 + 一个生态未知的组件
        ingest.ingest("t-unknown-eco", doc("com.example:known-lib", "1.0.0", "maven"));
        ingest.ingest("t-unknown-eco", docUnknownEco("mystery-lib", "1.0.0"));
        RiskReport report = risk.evaluate("t-unknown-eco");
        ComponentRisk known = find(report, "known-lib");
        ComponentRisk mystery = find(report, "mystery-lib");
        log.info("输入摘要: 1 个 maven 可判定组件 + 1 个生态未知组件 | maven 判定={} | 未知生态判定={} 依据={}",
                known.level(), mystery.level(), mystery.reasons());
        assertEquals(RiskLevel.CLEAN, known.level());
        assertEquals(RiskLevel.UNKNOWN, mystery.level());
        assertTrueReasonStartsWith(mystery, "UNKNOWN:unrecognized-ecosystem:unknown");
        // 总体结论：UNKNOWN 比 CLEAN 更需要关注
        assertEquals(RiskLevel.UNKNOWN, report.overallLevel());
    }

    @Test
    @DisplayName("跨生态隔离：npm 规则不会命中 maven 同名构件，maven 规则也不会命中 npm 包")
    void crossEcosystemRulesDoNotBleed() {
        // npm lodash 命中 npm 规则；maven 坐标 lodash:lodash 与 npm 的 lodash 是不同身份
        ingest.ingest("t-iso", """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"},
                  {"name":"lodash","version":"4.17.20","purl":"pkg:maven/lodash/lodash@4.17.20"},
                  {"name":"spring-beans","version":"5.3.16","ecosystems":["npm"]}
                ]}
                """);
        RiskReport report = risk.evaluate("t-iso");
        ComponentRisk npmLodash = find(report, "npm::lodash@");
        ComponentRisk mavenLodash = find(report, "maven::lodash:lodash@");
        ComponentRisk npmSpring = find(report, "npm::spring-beans@");
        log.info("输入摘要: npm lodash / maven lodash:lodash / npm spring-beans 同名跨生态 | "
                        + "判定: npm lodash={} maven lodash={} npm spring-beans={}",
                npmLodash.level(), mavenLodash.level(), npmSpring.level());
        report.components().forEach(c -> log.info("判定依据: {} => {} ({})",
                c.component(), c.level(), c.reasons()));
        assertEquals(RiskLevel.VULNERABLE, npmLodash.level());
        // maven 生态可判定、无 maven 规则命中 => CLEAN，绝不串 npm 的 CVE
        assertEquals(RiskLevel.CLEAN, mavenLodash.level());
        // npm 生态下名叫 spring-beans 的包不命中 maven 的 spring-beans 规则
        assertEquals(RiskLevel.CLEAN, npmSpring.level());
    }

    @Test
    @DisplayName("UNKNOWN 兜底：策略规则区间非法时无法判定，绝不默认安全")
    void illegalRangeYieldsUnknownNotClean() {
        rules.replace("test-bad-range-1",
                List.of(),
                List.of(new PolicyRule("POL-BAD", "unknown", "shady-lib",
                        ">=not-a-version", "bad range")));
        ingest.ingest("t4", doc("shady-lib", "1.0.0", "unknown"));
        ComponentRisk cr = risk.evaluate("t4").components().get(0);
        log.info("输入摘要: 命中组件但策略区间非法 | 判定: {} | 依据: {}", cr.level(), cr.reasons());
        assertEquals(RiskLevel.UNKNOWN, cr.level());
        assertTrueReasonStartsWith(cr, "UNKNOWN:illegal-policy-range:POL-BAD");
    }

    @Test
    @DisplayName("非法结构的规则替换被拒绝（空版本号），旧快照保持有效")
    void replacingWithIllegalStructureKeepsOldSnapshot() {
        String before = rules.version();
        assertThrows(IllegalArgumentException.class, () -> rules.replace("  ", List.of(), List.of()));
        log.warn("非法规则更新（空版本号）被拒绝，旧快照 {} 保留", before);
        assertEquals(before, rules.version());
        // 旧规则仍然可判定
        ingest.ingest("t6", doc("org.apache.logging.log4j:log4j-core", "2.14.0", "maven"));
        assertEquals(RiskLevel.VULNERABLE, risk.evaluate("t6").components().get(0).level());
    }

    @Test
    @DisplayName("可复现：相同输入与规则版本，两次判定逐字段一致；规则更新后结论相应变化")
    void verdictsAreReproducibleAndReactToRuleUpdates() {
        ingest.ingest("t5", doc("tracked-lib", "1.0.0", "unknown"));
        RiskReport r1 = risk.evaluate("t5");
        RiskReport r2 = risk.evaluate("t5");
        assertEquals(r1.components(), r2.components());
        assertEquals(r1.rulesVersion(), r2.rulesVersion());
        log.info("复现性校验: 两次判定 components 与 rulesVersion={} 完全一致", r1.rulesVersion());

        // 规则原子更新后，同一输入结论变为可复现的新结论
        rules.replace("2026-09-24",
                List.of(new VulnerabilityRule("CVE-NEW", "unknown", "tracked-lib",
                        List.of("=1.0.0"))),
                List.of());
        RiskReport r3 = risk.evaluate("t5");
        assertEquals(RiskLevel.VULNERABLE, r3.components().get(0).level());
        assertNotEquals(r1.rulesVersion(), r3.rulesVersion());
        log.info("规则更新后: rulesVersion={}，组件由 {} 变为 {}，依据={}",
                r3.rulesVersion(), r1.components().get(0).level(),
                r3.components().get(0).level(), r3.components().get(0).reasons());
    }

    @Test
    @DisplayName("目标不存在抛 TargetNotFoundException（由 Web 层映射为 404）")
    void unknownTargetIsRejected() {
        assertThrows(TargetNotFoundException.class, () -> risk.evaluate("no-such-target"));
    }

    @Test
    @DisplayName("无法判定条目进报告：不支持坐标类型的被拒条目单独列为 UNKNOWN 并抬高总体结论")
    void unsupportedCoordinateEntryAppearsInReportAndRaisesOverall() {
        // 真实场景：一份混合清单，大部分能判定，中间夹着一条暂不支持的坐标类型
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"com.example:clean-lib","version":"1.0.0","ecosystems":["maven"]},
                  {"name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0"},
                  {"name":"com.example:another-clean","version":"2.0.0","ecosystems":["maven"]}
                ]}
                """;
        ingest.ingest("t-mixed-unsupported", doc);
        RiskReport report = risk.evaluate("t-mixed-unsupported");
        log.info("输入摘要: 2 个可判定 maven 组件 + 1 条 pypi 坐标 | 报告条目数={} 总体={}",
                report.components().size(), report.overallLevel());
        assertEquals(3, report.components().size(), "被拒条目不能从报告里消失");
        ComponentRisk pypi = find(report, "pypi::requests@2.31.0");
        assertEquals(RiskLevel.UNKNOWN, pypi.level());
        assertTrueReasonStartsWith(pypi, "UNKNOWN:unsupported-coordinate-type:pypi");
        // 关键回归点：总体结论绝不能停在 CLEAN
        assertEquals(RiskLevel.UNKNOWN, report.overallLevel());
        report.components().forEach(c -> log.info("判定依据: {} => {} ({})",
                c.component(), c.level(), c.reasons()));
    }

    @Test
    @DisplayName("坐标写坏但标了 maven：即使无规则命中也是 UNKNOWN，绝不因 maven 标签放成 CLEAN")
    void malformedCoordinateLabeledMavenIsUnknown() {
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"some-maven-lib","version":"1.0.0",
                   "purl":"not-a-purl","ecosystems":["maven"]}
                ]}
                """;
        ingest.ingest("t-bad-purl-maven", doc);
        RiskReport report = risk.evaluate("t-bad-purl-maven");
        ComponentRisk cr = report.components().get(0);
        log.info("输入摘要: 畸形 purl + ecosystems=[maven]，无规则命中 | 判定={} 依据={}",
                cr.level(), cr.reasons());
        assertEquals(RiskLevel.UNKNOWN, cr.level());
        assertTrueReasonStartsWith(cr, "UNKNOWN:unreliable-coordinate:malformed-purl:");
        assertEquals(RiskLevel.UNKNOWN, report.overallLevel());
    }

    @Test
    @DisplayName("斜杠名字写法与大小写差异：归一到规则库身份，命中漏洞且只产生一条记录")
    void slashSpellingAndCaseMatchRulesAndDeduplicate() {
        String viaPurl = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"log4j-core","version":"2.14.0",
                   "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"}]}
                """;
        String viaSlashName = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"org.apache.logging.log4j/log4j-core","version":"2.14.0",
                   "ecosystems":["maven"]}]}
                """;
        String viaUpper = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"ORG.APACHE.LOGGING.LOG4J/LOG4J-CORE","version":"2.14.0",
                   "ecosystems":["MAVEN"]}]}
                """;
        var i1 = ingest.ingest("t-equiv", viaPurl);
        var i2 = ingest.ingest("t-equiv", viaSlashName);
        var i3 = ingest.ingest("t-equiv", viaUpper);
        log.info("输入摘要: 同一 Maven 库三种写法（purl / 斜杠名字 / 全大写）| accepted={},{},{} duplicate={},{},{}",
                i1.acceptedCount(), i2.acceptedCount(), i3.acceptedCount(),
                i1.duplicateCount(), i2.duplicateCount(), i3.duplicateCount());
        assertEquals(1, i1.acceptedCount());
        assertEquals(0, i2.acceptedCount());
        assertEquals(0, i3.acceptedCount());
        RiskReport report = risk.evaluate("t-equiv");
        assertEquals(1, report.components().size(), "等价写法必须只留一条记录");
        ComponentRisk cr = report.components().get(0);
        assertEquals("maven::org.apache.logging.log4j:log4j-core@2.14.0", cr.component());
        assertEquals(RiskLevel.VULNERABLE, cr.level(), "斜杠写法必须能匹配漏洞规则，不得判成安全");
        assertEquals(RiskLevel.VULNERABLE, report.overallLevel());
    }

    @Test
    @DisplayName("缺名/缺版本/非法版本的坏条目同样进报告列为 UNKNOWN，总体不低于 UNKNOWN")
    void malformedEntriesAppearInReportAsUnknown() {
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"version":"1.0.0"},
                  {"name":"no-version"},
                  {"name":"bad-version","version":"v1.0.0"},
                  {"name":"com.example:good","version":"1.0.0","ecosystems":["maven"]}
                ]}
                """;
        ingest.ingest("t-bad-entries", doc);
        RiskReport report = risk.evaluate("t-bad-entries");
        log.info("输入摘要: 3 条坏条目 + 1 条好条目 | 报告条目数={} 总体={}",
                report.components().size(), report.overallLevel());
        assertEquals(4, report.components().size());
        assertEquals(RiskLevel.UNKNOWN, report.overallLevel());
        long unknowns = report.components().stream()
                .filter(c -> c.level() == RiskLevel.UNKNOWN).count();
        assertEquals(3, unknowns);
    }

    private static void assertTrueReasonStartsWith(ComponentRisk cr, String prefix) {
        boolean ok = cr.reasons().stream().anyMatch(r -> r.startsWith(prefix));
        org.junit.jupiter.api.Assertions.assertTrue(ok,
                "expected a reason starting with " + prefix + " but got " + cr.reasons());
    }
}
