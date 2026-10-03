package com.github.lisama569.sbomriskservicejava.service;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.ComponentRisk;
import com.github.lisama569.sbomriskservicejava.model.PolicyRule;
import com.github.lisama569.sbomriskservicejava.model.RiskLevel;
import com.github.lisama569.sbomriskservicejava.model.RiskReport;
import com.github.lisama569.sbomriskservicejava.model.VulnerabilityRule;
import com.github.lisama569.sbomriskservicejava.rules.RuleRepository;
import com.github.lisama569.sbomriskservicejava.version.SemVer;
import com.github.lisama569.sbomriskservicejava.version.VersionParseException;
import com.github.lisama569.sbomriskservicejava.version.VersionRangeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * 风险判定服务。
 * <p>对目标下每个已接受组件，按当前规则快照判定：
 * <ol>
 *   <li>策略（拒绝名单）命中 → {@link RiskLevel#DENIED}；</li>
 *   <li>漏洞范围命中 → {@link RiskLevel#VULNERABLE}；</li>
 *   <li>无任何规则匹配 → {@link RiskLevel#CLEAN}；</li>
 *   <li>版本不可解析、生态无法识别（规则库未覆盖）、规则范围非法等无法判定的情况
 *       → {@link RiskLevel#UNKNOWN}，绝不能默认安全。</li>
 * </ol>
 * 报告携带规则版本；规则不变时，同一组件集合的报告逐条可复现。
 */
@Service
public class RiskEvaluationService {

    private static final Logger log = LoggerFactory.getLogger(RiskEvaluationService.class);

    /**
     * 规则库覆盖、可给出确定结论的生态。生态不在此集合（含 unknown）的组件
     * 无法确认是否命中规则，结论至少为 {@link RiskLevel#UNKNOWN}，绝不默认安全。
     */
    private static final java.util.Set<String> JUDGEABLE_ECOSYSTEMS = java.util.Set.of("maven", "npm");

    private final ComponentRepository componentRepository;
    private final RuleRepository ruleRepository;

    public RiskEvaluationService(ComponentRepository componentRepository, RuleRepository ruleRepository) {
        this.componentRepository = componentRepository;
        this.ruleRepository = ruleRepository;
    }

    /** 对目标下全部已摄入组件进行判定。目标不存在时抛 {@link TargetNotFoundException}。 */
    public RiskReport evaluate(String targetId) {
        if (targetId == null || targetId.isBlank()) {
            throw new IllegalArgumentException("targetId must not be blank");
        }
        List<Component> components = componentRepository.findByTarget(targetId);
        if (components.isEmpty()) {
            throw new TargetNotFoundException(targetId);
        }
        String rulesVersion = ruleRepository.version();
        log.info("Risk evaluation start | targetId={} | components={} | rulesVersion={}",
                targetId, components.size(), rulesVersion);

        List<ComponentRisk> risks = new ArrayList<>(components.size());
        RiskLevel overall = RiskLevel.CLEAN;
        for (Component c : components) {
            ComponentRisk risk = evaluateOne(c);
            risks.add(risk);
            if (risk.level().ordinal() > overall.ordinal()) {
                overall = risk.level();
            }
            log.info("Risk verdict | targetId={} | component={} | level={} | reasons={}",
                    targetId, risk.component(), risk.level(), risk.reasons());
        }
        // evaluatedAt 只记录判定时刻，不参与结论本身（结论由 组件集合+规则版本 唯一确定）
        RiskReport report = new RiskReport(targetId, overall, List.copyOf(risks),
                rulesVersion, Instant.now().toString());
        log.info("Risk evaluation done | targetId={} | overall={} | rulesVersion={}",
                targetId, overall, rulesVersion);
        return report;
    }

    private ComponentRisk evaluateOne(Component component) {
        SemVer version;
        try {
            version = SemVer.parse(component.version());
        } catch (VersionParseException e) {
            // 摄入阶段已拦截非法版本；防御性归入 UNKNOWN
            return new ComponentRisk(component.key(), RiskLevel.UNKNOWN,
                    List.of("UNKNOWN:cannot-parse-version:" + e.getMessage()));
        }

        List<String> reasons = new ArrayList<>();

        // 0. 生态不可识别 → 无法确认规则覆盖，先记无法判定（规则仍照常匹配，
        //    命中的 DENIED/VULNERABLE 更严重等级仍然优先）
        boolean unjudgeable = false;
        String ecosystem = component.ecosystem() == null
                ? "unknown" : component.ecosystem().trim().toLowerCase();
        if (!JUDGEABLE_ECOSYSTEMS.contains(ecosystem)) {
            unjudgeable = true;
            reasons.add("UNKNOWN:unrecognized-ecosystem:" + ecosystem);
        }

        // 1. 策略优先（DENIED）
        List<PolicyRule> policies = ruleRepository.findPolicies(component);
        boolean denied = false;
        for (PolicyRule policy : policies) {
            try {
                if (ruleRepository.policyMatches(policy, version)) {
                    denied = true;
                    reasons.add("DENIED:" + policy.id() + ":" + policy.message());
                }
            } catch (VersionRangeException e) {
                unjudgeable = true;
                reasons.add("UNKNOWN:illegal-policy-range:" + policy.id() + ":" + e.getMessage());
            }
        }
        if (denied) {
            return new ComponentRisk(component.key(), RiskLevel.DENIED, List.copyOf(reasons));
        }

        // 2. 漏洞（VULNERABLE）
        List<VulnerabilityRule> vulns = ruleRepository.findVulnerabilities(component);
        boolean vulnerable = false;
        for (VulnerabilityRule vuln : vulns) {
            try {
                if (ruleRepository.rangeMatches(vuln, version)) {
                    vulnerable = true;
                    reasons.add("VULNERABLE:" + vuln.id() + ":in-range" + vuln.affectedRanges());
                }
            } catch (VersionRangeException e) {
                unjudgeable = true;
                reasons.add("UNKNOWN:illegal-vuln-range:" + vuln.id() + ":" + e.getMessage());
            }
        }
        if (vulnerable) {
            return new ComponentRisk(component.key(), RiskLevel.VULNERABLE, List.copyOf(reasons));
        }
        if (unjudgeable) {
            return new ComponentRisk(component.key(), RiskLevel.UNKNOWN, List.copyOf(reasons));
        }

        // 3. 无规则匹配且可判定 → CLEAN（明确依据，而非缺省值）
        if (policies.isEmpty() && vulns.isEmpty()) {
            reasons.add("CLEAN:no-rules-matched");
        } else {
            reasons.add("CLEAN:all-ranges-excluded");
        }
        return new ComponentRisk(component.key(), RiskLevel.CLEAN, List.copyOf(reasons));
    }
}
