package com.github.lisama569.sbomriskservicejava.model;

/**
 * Locally maintained policy rule.
 *
 * @param id         rule id
 * @param type       BAN or LICENSE_DENY
 * @param ecosystem  package ecosystem (null matches any)
 * @param name       component name for BAN; null when license based
 * @param range      affected version range expression; "*" means all versions
 * @param license    denied license for LICENSE_DENY; null otherwise
 * @param severity   severity label
 */
public record PolicyRule(
        String id,
        PolicyType type,
        String ecosystem,
        String name,
        String range,
        String license,
        String severity
) {
}
