package com.github.lisama569.sbomriskservicejava.rule;

import com.github.lisama569.sbomriskservicejava.exception.RuleConfigurationException;
import com.github.lisama569.sbomriskservicejava.model.PolicyRule;
import com.github.lisama569.sbomriskservicejava.model.PolicyType;
import com.github.lisama569.sbomriskservicejava.model.VulnerabilityRule;
import com.github.lisama569.sbomriskservicejava.version.RangeExpression;
import com.github.lisama569.sbomriskservicejava.version.RangeMatcher;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentSkipListMap;

/**
 * In-memory, locally maintained rule store.
 *
 * <p>Rules are kept in id-sorted order so matching and API output are
 * deterministic. Adding or replacing a rule validates the affected-version
 * range eagerly: an invalid range is rejected with
 * {@link RuleConfigurationException} (INVALID_RULE) rather than being stored.
 */
@Repository
public class RuleRepository {

    private final ConcurrentSkipListMap<String, VulnerabilityRule> vulnerabilities = new ConcurrentSkipListMap<>();
    private final ConcurrentSkipListMap<String, PolicyRule> policies = new ConcurrentSkipListMap<>();

    public List<VulnerabilityRule> findVulnerabilities(String ecosystem, String name) {
        String eco = normalize(ecosystem);
        return vulnerabilities.values().stream()
                .filter(r -> matchesEco(normalize(r.ecosystem()), eco))
                .filter(r -> r.name().equalsIgnoreCase(name))
                .toList();
    }

    public List<PolicyRule> findPolicies(String ecosystem, String name, String license) {
        String eco = normalize(ecosystem);
        return policies.values().stream()
                .filter(r -> matchesEco(normalize(r.ecosystem()), eco))
                .filter(r -> matchesPolicyTarget(r, name, license))
                .toList();
    }

    private boolean matchesPolicyTarget(PolicyRule r, String name, String license) {
        return switch (r.type()) {
            case BAN -> r.name() != null && r.name().equalsIgnoreCase(name);
            case LICENSE_DENY -> r.license() != null && r.license().equalsIgnoreCase(license);
        };
    }

    private static boolean matchesEco(String ruleEco, String componentEco) {
        // null/blank ecosystem on a rule means it applies to every ecosystem
        return ruleEco == null || ruleEco.equals(componentEco);
    }

    private static String normalize(String s) {
        return s == null || s.isBlank() ? null : s.trim().toLowerCase();
    }

    public VulnerabilityRule addVulnerability(VulnerabilityRule rule) {
        validate(rule);
        RangeExpression parsed = RangeMatcher.parse(rule.range()); // throws on invalid grammar
        vulnerabilities.put(rule.id(), rule);
        return rule;
    }

    public PolicyRule addPolicy(PolicyRule rule) {
        validate(rule);
        RangeMatcher.parse(rule.range());
        policies.put(rule.id(), rule);
        return rule;
    }

    private void validate(VulnerabilityRule rule) {
        if (rule == null) {
            throw new RuleConfigurationException("vulnerability rule is null");
        }
        requireText(rule.id(), "vulnerability rule id");
        requireText(rule.name(), "vulnerability rule component name");
        requireText(rule.range(), "vulnerability rule affected range");
    }

    private void validate(PolicyRule rule) {
        if (rule == null) {
            throw new RuleConfigurationException("policy rule is null");
        }
        requireText(rule.id(), "policy rule id");
        requireText(rule.range(), "policy rule range");
        if (rule.type() == null) {
            throw new RuleConfigurationException("policy rule type is required (BAN or LICENSE_DENY)");
        }
        if (rule.type() == PolicyType.BAN && (rule.name() == null || rule.name().isBlank())) {
            throw new RuleConfigurationException("BAN policy requires a component name");
        }
        if (rule.type() == PolicyType.LICENSE_DENY && (rule.license() == null || rule.license().isBlank())) {
            throw new RuleConfigurationException("LICENSE_DENY policy requires a license");
        }
    }

    private static void requireText(String value, String what) {
        if (value == null || value.isBlank()) {
            throw new RuleConfigurationException(what + " is required");
        }
    }

    public Optional<VulnerabilityRule> findVulnerabilityById(String id) {
        return Optional.ofNullable(vulnerabilities.get(id));
    }

    public Optional<PolicyRule> findPolicyById(String id) {
        return Optional.ofNullable(policies.get(id));
    }

    public List<VulnerabilityRule> allVulnerabilities() {
        return List.copyOf(vulnerabilities.values());
    }

    public List<PolicyRule> allPolicies() {
        return List.copyOf(policies.values());
    }
}
