package com.github.lisama569.sbomriskservicejava.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.PolicyRule;
import com.github.lisama569.sbomriskservicejava.model.VulnerabilityRule;
import com.github.lisama569.sbomriskservicejava.version.SemVer;
import com.github.lisama569.sbomriskservicejava.version.VersionRange;
import com.github.lisama569.sbomriskservicejava.version.VersionRangeException;
import jakarta.annotation.PostConstruct;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 本地漏洞与策略规则仓库。
 * <p>启动时从 classpath 的 {@code rules/vulnerabilities.json} 与
 * {@code rules/policies.json} 加载；所有版本区间在加载/替换时预编译，
 * 非法区间导致本次加载/替换被明确拒绝（快速失败，结论不会不确定）。
 * <p>规则以不可变快照持有，{@link #replace} 原子切换；快照版本号
 * （{@link #version()}）随风险报告返回，保证结论可复现。
 * <p>匹配键为 {@code ecosystem(小写)::name(小写)}。
 */
@Repository
public class RuleRepository {

    static final String VULN_RESOURCE = "rules/vulnerabilities.json";
    static final String POLICY_RESOURCE = "rules/policies.json";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private volatile Snapshot snapshot = Snapshot.empty("unloaded");

    @PostConstruct
    public void loadDefaults() {
        List<VulnerabilityRule> vulns = readVulnerabilities(VULN_RESOURCE);
        List<PolicyRule> policies = readPolicies(POLICY_RESOURCE);
        String vVersion = readVersion(VULN_RESOURCE);
        String pVersion = readVersion(POLICY_RESOURCE);
        String version = "vulns=" + vVersion + "/policies=" + pVersion;
        replace(version, vulns, policies);
    }

    /** 当前规则版本（写入风险报告，用于结论复现）。 */
    public String version() {
        return snapshot.version;
    }

    /**
     * 原子替换全部规则快照。规则结构非法（缺字段等）快速失败；
     * 版本区间允许延迟到判定时校验，非法区间的相关组件结论为 UNKNOWN。
     */
    public void replace(String version, List<VulnerabilityRule> vulns, List<PolicyRule> policies) {
        if (version == null || version.isBlank()) {
            throw new IllegalArgumentException("rule version must not be blank");
        }
        this.snapshot = Snapshot.of(version,
                vulns == null ? List.of() : vulns,
                policies == null ? List.of() : policies);
    }

    /** 查匹配生态+名称的漏洞规则（范围在 {@link #rangeMatches} 中判定）。 */
    public List<VulnerabilityRule> findVulnerabilities(Component component) {
        return snapshot.vulnsByKey.getOrDefault(key(component.ecosystem(), component.name()), List.of());
    }

    /** 查匹配生态+名称的策略规则（范围在 {@link #policyMatches} 中判定）。 */
    public List<PolicyRule> findPolicies(Component component) {
        return snapshot.policiesByKey.getOrDefault(key(component.ecosystem(), component.name()), List.of());
    }

    /** 判断漏洞规则的任一 OR 范围是否命中版本；区间非法时抛 {@link VersionRangeException}。 */
    public boolean rangeMatches(VulnerabilityRule rule, SemVer version) {
        for (VersionRange r : snapshot.vulnRanges(rule)) {
            if (r.contains(version)) {
                return true;
            }
        }
        return false;
    }

    /** 判断策略规则是否命中；range 为 null 表示所有版本；区间非法时抛 {@link VersionRangeException}。 */
    public boolean policyMatches(PolicyRule rule, SemVer version) {
        VersionRange range = snapshot.policyRange(rule);
        return range == null || range.contains(version);
    }

    static String key(String ecosystem, String name) {
        return (ecosystem == null ? "unknown" : ecosystem.trim().toLowerCase())
                + "::" + (name == null ? "" : name.trim().toLowerCase());
    }

    // ---------- 资源读取 ----------

    private String readVersion(String resource) {
        JsonNode root = readJson(resource);
        JsonNode v = root.get("version");
        return v == null || v.asText().isBlank() ? "unknown" : v.asText();
    }

    private List<VulnerabilityRule> readVulnerabilities(String resource) {
        JsonNode root = readJson(resource);
        JsonNode arr = root.get("vulnerabilities");
        if (arr == null || !arr.isArray()) {
            throw new IllegalStateException("missing 'vulnerabilities' array in " + resource);
        }
        List<VulnerabilityRule> result = new ArrayList<>();
        for (JsonNode n : arr) {
            List<String> ranges = new ArrayList<>();
            JsonNode rangeNode = n.get("affectedRanges");
            if (rangeNode != null && rangeNode.isArray()) {
                rangeNode.forEach(r -> ranges.add(r.asText()));
            }
            result.add(new VulnerabilityRule(
                    required(n, "id", resource),
                    required(n, "ecosystem", resource),
                    required(n, "name", resource),
                    List.copyOf(ranges)));
        }
        return result;
    }

    private List<PolicyRule> readPolicies(String resource) {
        JsonNode root = readJson(resource);
        JsonNode arr = root.get("policies");
        if (arr == null || !arr.isArray()) {
            throw new IllegalStateException("missing 'policies' array in " + resource);
        }
        List<PolicyRule> result = new ArrayList<>();
        for (JsonNode n : arr) {
            JsonNode range = n.get("range");
            result.add(new PolicyRule(
                    required(n, "id", resource),
                    required(n, "ecosystem", resource),
                    required(n, "name", resource),
                    range == null || range.isNull() ? null : range.asText(),
                    n.path("message").asText("denied by local policy")));
        }
        return result;
    }

    private static String required(JsonNode node, String field, String resource) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull() || v.asText().isBlank()) {
            throw new IllegalStateException("missing required field '" + field + "' in " + resource);
        }
        return v.asText();
    }

    private JsonNode readJson(String resource) {
        try (InputStream in = new ClassPathResource(resource).getInputStream()) {
            JsonNode root = objectMapper.readTree(in);
            if (root == null || !root.isObject()) {
                throw new IllegalStateException("root of " + resource + " must be a JSON object");
            }
            return root;
        } catch (IOException e) {
            throw new IllegalStateException("cannot read rule resource " + resource + ": " + e.getMessage(), e);
        }
    }

    // ---------- 不可变快照 ----------

    /**
     * 规则快照。版本区间<b>懒编译</b>：非法区间不阻止规则入库，
     * 评估相关组件时抛出 {@link VersionRangeException}，由判定服务归入 UNKNOWN；
     * 合法区间首次编译后缓存，保证判定确定且可复现。
     */
    private static final class Snapshot {

        private final String version;
        private final Map<String, List<VulnerabilityRule>> vulnsByKey;
        private final Map<String, List<PolicyRule>> policiesByKey;
        private final Map<VulnerabilityRule, List<VersionRange>> compiledVulnRanges =
                new HashMap<>();
        private final Map<PolicyRule, VersionRange> compiledPolicyRanges = new HashMap<>();

        private Snapshot(String version,
                         Map<String, List<VulnerabilityRule>> vulnsByKey,
                         Map<String, List<PolicyRule>> policiesByKey) {
            this.version = version;
            this.vulnsByKey = vulnsByKey;
            this.policiesByKey = policiesByKey;
        }

        static Snapshot empty(String version) {
            return new Snapshot(version, Map.of(), Map.of());
        }

        static Snapshot of(String version, List<VulnerabilityRule> vulns, List<PolicyRule> policies) {
            Map<String, List<VulnerabilityRule>> vMap = new HashMap<>();
            for (VulnerabilityRule v : vulns) {
                vMap.computeIfAbsent(key(v.ecosystem(), v.name()), k -> new ArrayList<>()).add(v);
            }
            Map<String, List<PolicyRule>> pMap = new HashMap<>();
            for (PolicyRule p : policies) {
                pMap.computeIfAbsent(key(p.ecosystem(), p.name()), k -> new ArrayList<>()).add(p);
            }
            return new Snapshot(version, immutable(vMap), immutable(pMap));
        }

        synchronized List<VersionRange> vulnRanges(VulnerabilityRule rule) {
            List<VersionRange> cached = compiledVulnRanges.get(rule);
            if (cached != null) {
                return cached;
            }
            try {
                List<VersionRange> ranges = VersionRange.compileAny(rule.affectedRanges());
                compiledVulnRanges.put(rule, ranges);
                return ranges;
            } catch (VersionRangeException e) {
                throw new VersionRangeException(
                        "illegal affected range in vulnerability rule " + rule.id() + ": " + e.getMessage());
            }
        }

        /** 无范围（null/blank）返回 null，表示所有版本。 */
        synchronized VersionRange policyRange(PolicyRule rule) {
            if (rule.range() == null || rule.range().isBlank()) {
                return null;
            }
            if (compiledPolicyRanges.containsKey(rule)) {
                return compiledPolicyRanges.get(rule);
            }
            try {
                VersionRange range = VersionRange.compile(rule.range());
                compiledPolicyRanges.put(rule, range);
                return range;
            } catch (VersionRangeException e) {
                throw new VersionRangeException(
                        "illegal range in policy rule " + rule.id() + ": " + e.getMessage());
            }
        }

        /** 允许 null 值的不可变 Map 拷贝。 */
        private static <K, V> Map<K, V> immutable(Map<K, V> source) {
            return Collections.unmodifiableMap(new HashMap<>(source));
        }
    }
}
