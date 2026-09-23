package com.github.lisama569.sbomriskservicejava.rule;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.sbomriskservicejava.exception.RuleConfigurationException;
import com.github.lisama569.sbomriskservicejava.model.PolicyRule;
import com.github.lisama569.sbomriskservicejava.model.PolicyType;
import com.github.lisama569.sbomriskservicejava.model.VulnerabilityRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.InputStream;

/**
 * Loads the bundled {@code classpath:/rules.json} into the repository on
 * startup. The resource is fixed, so a fresh instance always evaluates the
 * same input against the same rules and gets the same verdict.
 *
 * <p>A syntactically invalid bundled rule fails fast with
 * {@link RuleConfigurationException}; it is never silently skipped.
 */
@Component
public class RuleLoader implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(RuleLoader.class);

    private final RuleRepository repository;
    private final ObjectMapper objectMapper;

    public RuleLoader(RuleRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    @Override
    public void run(ApplicationArguments args) {
        ClassPathResource resource = new ClassPathResource("rules.json");
        if (!resource.exists()) {
            log.warn("no bundled rules.json found; starting with an empty rule set");
            return;
        }
        try (InputStream in = resource.getInputStream()) {
            JsonNode root = objectMapper.readTree(in);
            int vulnerabilities = loadVulnerabilities(root);
            int policies = loadPolicies(root);
            log.info("loaded local rules: {} vulnerabilities, {} policies", vulnerabilities, policies);
        } catch (RuleConfigurationException e) {
            throw e;
        } catch (Exception e) {
            throw new RuleConfigurationException("failed to load bundled rules.json: " + e.getMessage(), e);
        }
    }

    private int loadVulnerabilities(JsonNode root) {
        JsonNode array = root.get("vulnerabilities");
        if (array == null || !array.isArray()) {
            return 0;
        }
        int count = 0;
        for (JsonNode node : array) {
            VulnerabilityRule rule = new VulnerabilityRule(
                    text(node, "id"),
                    text(node, "ecosystem"),
                    text(node, "name"),
                    text(node, "range"),
                    text(node, "severity"));
            repository.addVulnerability(rule);
            count++;
        }
        return count;
    }

    private int loadPolicies(JsonNode root) {
        JsonNode array = root.get("policies");
        if (array == null || !array.isArray()) {
            return 0;
        }
        int count = 0;
        for (JsonNode node : array) {
            String typeText = text(node, "type");
            PolicyType type;
            try {
                type = PolicyType.valueOf(typeText);
            } catch (IllegalArgumentException e) {
                throw new RuleConfigurationException("unknown policy type '" + typeText + "'");
            }
            PolicyRule rule = new PolicyRule(
                    text(node, "id"),
                    type,
                    text(node, "ecosystem"),
                    text(node, "name"),
                    text(node, "range"),
                    text(node, "license"),
                    text(node, "severity"));
            repository.addPolicy(rule);
            count++;
        }
        return count;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual()) {
            throw new RuleConfigurationException("rule field '" + field + "' must be a string");
        }
        return value.asText();
    }
}
