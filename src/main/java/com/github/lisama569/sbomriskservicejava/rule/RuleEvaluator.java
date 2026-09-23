package com.github.lisama569.sbomriskservicejava.rule;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.Finding;
import com.github.lisama569.sbomriskservicejava.model.PolicyRule;
import com.github.lisama569.sbomriskservicejava.model.RiskAssessment;
import com.github.lisama569.sbomriskservicejava.model.Verdict;
import com.github.lisama569.sbomriskservicejava.model.VulnerabilityRule;
import com.github.lisama569.sbomriskservicejava.version.ParseResult;
import com.github.lisama569.sbomriskservicejava.version.RangeExpression;
import com.github.lisama569.sbomriskservicejava.version.RangeMatcher;
import com.github.lisama569.sbomriskservicejava.version.Version;
import com.github.lisama569.sbomriskservicejava.version.VersionParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates a normalized component against the locally maintained rules and
 * produces a deterministic {@link RiskAssessment}.
 *
 * <p>Verdict rules (in priority order):
 * <ol>
 *   <li>VULNERABLE — at least one vulnerability rule's affected range matches.</li>
 *   <li>POLICY_VIOLATION — at least one policy rule's range matches.</li>
 *   <li>UNKNOWN — a candidate rule's bound is incomparable with the version,
 *       or the version itself cannot be parsed. Never defaults to safe.</li>
 *   <li>SAFE — no rule matches; an explicit conclusion given the fixed rule set.</li>
 * </ol>
 * Rules are inspected in id-sorted order, which makes every assessment
 * reproducible for the same rules and component.
 */
@Service
public class RuleEvaluator {

    private static final Logger log = LoggerFactory.getLogger(RuleEvaluator.class);

    private final RuleRepository repository;

    public RuleEvaluator(RuleRepository repository) {
        this.repository = repository;
    }

    public RiskAssessment assess(Component component) {
        log.info("risk input: key={}, name={}, version={}, purl={}, ecosystem={}, license={}",
                component.key(), component.name(), component.version(),
                component.purl(), component.ecosystem(), component.license());

        ParseResult parsed = VersionParser.parseLenient(component.version());
        if (parsed instanceof ParseResult.Error err) {
            return unknown(component, "INVALID_VERSION: " + err.detail());
        }
        Version version = ((ParseResult.Ok) parsed).value();

        List<Finding> findings = new ArrayList<>();
        boolean vulnerable = false;
        boolean policyViolation = false;
        boolean incomparable = false;
        List<String> unknownBasis = new ArrayList<>();

        for (VulnerabilityRule rule : repository.findVulnerabilities(component.ecosystem(), component.name())) {
            RangeExpression range = RangeMatcher.parse(rule.range());
            Boolean hit = RangeMatcher.matches(range, version);
            if (hit == null) {
                incomparable = true;
                unknownBasis.add(rule.id() + " range '" + rule.range()
                        + "' is incomparable with version '" + version.raw() + "'");
                continue;
            }
            if (hit) {
                vulnerable = true;
                findings.add(new Finding(rule.id(), "VULNERABILITY", rule.severity(),
                        rule.range(), "version '" + version.raw() + "' is within affected range '"
                                + rule.range() + "'"));
            }
        }

        for (PolicyRule rule : repository.findPolicies(component.ecosystem(), component.name(), component.license())) {
            RangeExpression range = RangeMatcher.parse(rule.range());
            Boolean hit = RangeMatcher.matches(range, version);
            if (hit == null) {
                incomparable = true;
                unknownBasis.add(rule.id() + " range '" + rule.range()
                        + "' is incomparable with version '" + version.raw() + "'");
                continue;
            }
            if (hit) {
                policyViolation = true;
                String detail = rule.type().name().equals("LICENSE_DENY")
                        ? "license '" + component.license() + "' is denied"
                        : "component is banned";
                findings.add(new Finding(rule.id(), rule.type().name(), rule.severity(),
                        rule.range(), detail + " and version '" + version.raw()
                                + "' is within policy range '" + rule.range() + "'"));
            }
        }

        Verdict verdict;
        String unknownReason = null;
        if (vulnerable) {
            verdict = Verdict.VULNERABLE;
        } else if (policyViolation) {
            verdict = Verdict.POLICY_VIOLATION;
        } else if (incomparable) {
            verdict = Verdict.UNKNOWN;
            unknownReason = "VERSION_INCOMPARABLE: " + String.join("; ", unknownBasis);
        } else {
            verdict = Verdict.SAFE;
        }

        RiskAssessment assessment = new RiskAssessment(
                component.key(), component.name(), component.version(),
                verdict, unknownReason, List.copyOf(findings));
        log.info("risk verdict: key={}, version={}, verdict={}, matchedRules={}, basis={}",
                component.key(), component.version(), verdict,
                findings.stream().map(Finding::ruleId).toList(),
                unknownReason != null ? unknownReason
                        : findings.isEmpty() ? "no local rule applies to this component"
                        : findings.stream().map(Finding::basis).toList());
        return assessment;
    }

    private RiskAssessment unknown(Component component, String reason) {
        log.info("risk verdict: key={}, version={}, verdict=UNKNOWN, basis={}",
                component.key(), component.version(), reason);
        return new RiskAssessment(component.key(), component.name(), component.version(),
                Verdict.UNKNOWN, reason, List.of());
    }
}
