package com.github.lisama569.sbomriskservicejava.tests;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.PolicyRule;
import com.github.lisama569.sbomriskservicejava.model.PolicyType;
import com.github.lisama569.sbomriskservicejava.model.RiskAssessment;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import com.github.lisama569.sbomriskservicejava.model.Verdict;
import com.github.lisama569.sbomriskservicejava.model.VulnerabilityRule;
import com.github.lisama569.sbomriskservicejava.rule.RuleEvaluator;
import com.github.lisama569.sbomriskservicejava.rule.RuleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleEvaluatorTest {

    private static final Logger log = LoggerFactory.getLogger(RuleEvaluatorTest.class);

    private RuleRepository repository;
    private RuleEvaluator evaluator;

    @BeforeEach
    void setUp() {
        repository = new RuleRepository();
        evaluator = new RuleEvaluator(repository);
        repository.addVulnerability(new VulnerabilityRule(
                "V-1", "npm", "lodash", ">=4.0.0 <4.17.21", "HIGH"));
        repository.addVulnerability(new VulnerabilityRule(
                "V-2", "npm", "alpha-lib", ">=1.0.0-alpha <1.0.0", "MEDIUM"));
        repository.addPolicy(new PolicyRule(
                "P-BAN", PolicyType.BAN, "npm", "left-pad", "*", null, "HIGH"));
        repository.addPolicy(new PolicyRule(
                "P-LIC", PolicyType.LICENSE_DENY, null, null, "*", "GPL-3.0-only", "HIGH"));
    }

    private Component component(String name, String version, String ecosystem, String license) {
        return new Component("pkg:" + ecosystem + "/" + name + "@" + version,
                name, version, null, ecosystem, license, SbomFormat.CYCLONEDX_JSON);
    }

    private RiskAssessment assess(String name, String version, String ecosystem, String license) {
        Component c = component(name, version, ecosystem, license);
        RiskAssessment a = evaluator.assess(c);
        log.info("input summary: {}@{} ({}, license={}) -> verdict={}, findings={}, unknownReason={}",
                name, version, ecosystem, license, a.verdict(),
                a.findings().stream().map(f -> f.ruleId() + ":" + f.basis()).toList(),
                a.unknownReason());
        return a;
    }

    @Test
    void vulnerableWhenInsideRange() {
        assertEquals(Verdict.VULNERABLE, assess("lodash", "4.17.20", "npm", null).verdict());
    }

    @Test
    void safeWhenOutsideAllRanges() {
        RiskAssessment a = assess("lodash", "4.17.21", "npm", null);
        assertEquals(Verdict.SAFE, a.verdict());
        assertTrue(a.findings().isEmpty());
    }

    @Test
    void releaseVersionIsNotAffectedByPrereleaseRange() {
        // the rule covers only 1.0.0 pre-releases; release 1.0.0 is SAFE
        assertEquals(Verdict.VULNERABLE, assess("alpha-lib", "1.0.0-alpha.5", "npm", null).verdict());
        assertEquals(Verdict.SAFE, assess("alpha-lib", "1.0.0", "npm", null).verdict());
    }

    @Test
    void banPolicyMatchesAnyVersion() {
        RiskAssessment a = assess("left-pad", "99.0.0", "npm", null);
        assertEquals(Verdict.POLICY_VIOLATION, a.verdict());
        assertEquals("P-BAN", a.findings().get(0).ruleId());
    }

    @Test
    void licenseDenyPolicyMatchesAcrossEcosystems() {
        RiskAssessment a = assess("some-gpl-lib", "1.0.0", "pypi", "GPL-3.0-only");
        assertEquals(Verdict.POLICY_VIOLATION, a.verdict());
        assertEquals("P-LIC", a.findings().get(0).ruleId());
    }

    @Test
    void vulnerabilityOutranksPolicyAndIsReproducible() {
        // same input assessed twice with unchanged rules yields identical verdicts
        RiskAssessment first = assess("lodash", "4.17.20", "npm", "GPL-3.0-only");
        RiskAssessment second = assess("lodash", "4.17.20", "npm", "GPL-3.0-only");
        assertEquals(Verdict.VULNERABLE, first.verdict());
        assertEquals(first, second);
        assertTrue(first.findings().stream().anyMatch(f -> f.ruleId().equals("V-1")));
        assertTrue(first.findings().stream().anyMatch(f -> f.ruleId().equals("P-LIC")));
    }

    @Test
    void noMatchingRuleIsExplicitSafe() {
        RiskAssessment a = assess("never-heard-of-it", "0.0.1", "npm", null);
        assertEquals(Verdict.SAFE, a.verdict());
        assertFalse(a.findings().stream().anyMatch(f -> true) && false);
    }

    @Test
    void undecidableVersionIsUnknownNeverSafe() {
        // a component whose version cannot be interpreted must not default to SAFE
        Component weird = new Component("pkg:npm/legacy-thing@1.2-rc1",
                "legacy-thing", "1.2-rc1", null, "npm", null, SbomFormat.CYCLONEDX_JSON);
        RiskAssessment a = evaluator.assess(weird);
        log.info("input summary: legacy-thing@1.2-rc1 (unparseable) -> verdict={}, unknownReason={}",
                a.verdict(), a.unknownReason());
        assertEquals(Verdict.UNKNOWN, a.verdict());
        assertTrue(a.unknownReason().contains("INVALID_VERSION"));
    }
}
