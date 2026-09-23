package com.github.lisama569.sbomriskservicejava.web;

import com.github.lisama569.sbomriskservicejava.model.PolicyRule;
import com.github.lisama569.sbomriskservicejava.model.VulnerabilityRule;
import com.github.lisama569.sbomriskservicejava.rule.RuleRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Administrative API for the locally maintained rule set.
 */
@RestController
@RequestMapping("/api/v1/rules")
public class RuleAdminController {

    private final RuleRepository repository;

    public RuleAdminController(RuleRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/vulnerabilities")
    public List<VulnerabilityRule> listVulnerabilities() {
        return repository.allVulnerabilities();
    }

    @GetMapping("/policies")
    public List<PolicyRule> listPolicies() {
        return repository.allPolicies();
    }

    @PostMapping("/vulnerabilities")
    public ResponseEntity<VulnerabilityRule> addVulnerability(@RequestBody VulnerabilityRule rule) {
        return ResponseEntity.ok(repository.addVulnerability(rule));
    }

    @PostMapping("/policies")
    public ResponseEntity<PolicyRule> addPolicy(@RequestBody PolicyRule rule) {
        return ResponseEntity.ok(repository.addPolicy(rule));
    }
}
