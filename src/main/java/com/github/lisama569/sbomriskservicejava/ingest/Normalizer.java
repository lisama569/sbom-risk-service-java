package com.github.lisama569.sbomriskservicejava.ingest;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.RejectedEntry;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import com.github.lisama569.sbomriskservicejava.version.ParseResult;
import com.github.lisama569.sbomriskservicejava.version.VersionParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Normalizes parsed entries into the unified {@link Component} model.
 *
 * <p>Validation order gives one distinguishable reason per bad entry:
 * <ol>
 *   <li>non-object entry → INVALID_ENTRY</li>
 *   <li>missing name → MISSING_NAME</li>
 *   <li>missing version → MISSING_VERSION</li>
 *   <li>unparseable version → INVALID_VERSION</li>
 *   <li>present but malformed purl, or no purl and no name fallback → MISSING_IDENTIFIER</li>
 * </ol>
 * Entries are never silently skipped.
 */
@org.springframework.stereotype.Component
public class Normalizer {

    private static final Logger log = LoggerFactory.getLogger(Normalizer.class);

    public NormalizationOutcome normalize(ParsedEntry entry, SbomFormat source) {
        String displayName = entry.name();
        String displayVersion = entry.version();

        if (entry.name() == null || entry.name().isBlank()) {
            return reject(entry.index(), displayName, displayVersion,
                    com.github.lisama569.sbomriskservicejava.model.RejectReason.MISSING_NAME,
                    "entry has no component name");
        }
        if (entry.version() == null || entry.version().isBlank()) {
            return reject(entry.index(), displayName, displayVersion,
                    com.github.lisama569.sbomriskservicejava.model.RejectReason.MISSING_VERSION,
                    "entry '" + entry.name() + "' has no version");
        }
        ParseResult versionParse = VersionParser.parseLenient(entry.version());
        if (versionParse instanceof ParseResult.Error err) {
            return reject(entry.index(), displayName, displayVersion,
                    com.github.lisama569.sbomriskservicejava.model.RejectReason.INVALID_VERSION,
                    err.detail());
        }

        String purl = entry.purl();
        PurlSupport.ParsedPurl parsedPurl = null;
        if (purl != null && !purl.isBlank()) {
            parsedPurl = PurlSupport.parse(purl);
            if (parsedPurl == null) {
                return reject(entry.index(), displayName, displayVersion,
                        com.github.lisama569.sbomriskservicejava.model.RejectReason.MISSING_IDENTIFIER,
                        "malformed package url: '" + purl + "'");
            }
        }

        String ecosystem = entry.ecosystem() != null && !entry.ecosystem().isBlank()
                ? entry.ecosystem().trim().toLowerCase()
                : parsedPurl != null ? parsedPurl.type() : null;
        String rawName = entry.name().trim();
        // For ecosystems whose identity is namespace-qualified (e.g. Maven
        // groupId:artifactId), rule names may use the fully qualified form.
        String name = qualifiedName(ecosystem, rawName, parsedPurl != null ? parsedPurl.namespace() : null);
        String key = parsedPurl != null
                ? parsedPurl.canonical()
                : syntheticKey(ecosystem, rawName, entry.version().trim());
        if (key == null) {
            return reject(entry.index(), displayName, displayVersion,
                    com.github.lisama569.sbomriskservicejava.model.RejectReason.MISSING_IDENTIFIER,
                    "entry '" + name + "' has neither a purl nor an ecosystem to build an identity");
        }

        Component component = new Component(
                key,
                name,
                entry.version().trim(),
                parsedPurl != null ? purl.trim() : null,
                ecosystem,
                entry.license(),
                source);
        log.debug("normalized entry[{}] -> key={}", entry.index(), key);
        return new NormalizationOutcome.Accepted(component);
    }

    private static String syntheticKey(String ecosystem, String name, String version) {
        if (ecosystem == null || ecosystem.isBlank()) {
            return null;
        }
        return "pkg:" + ecosystem.trim().toLowerCase() + "/" + name + "@" + version;
    }

    /**
     * Maven coordinates are only unique with their groupId, so the component
     * name used for rule matching is {@code groupId:artifactId} when the purl
     * carries a namespace. Other ecosystems keep the plain name.
     */
    private static String qualifiedName(String ecosystem, String rawName, String namespace) {
        if ("maven".equals(ecosystem) && namespace != null && !namespace.isBlank()) {
            return namespace + ":" + rawName;
        }
        return rawName;
    }

    private static NormalizationOutcome reject(int index, String name, String version,
                                               com.github.lisama569.sbomriskservicejava.model.RejectReason reason,
                                               String detail) {
        log.info("rejected entry[{}] name={} version={} reason={} detail={}",
                index, name, version, reason, detail);
        return new NormalizationOutcome.Rejected(new RejectedEntry(index, name, version, reason, detail));
    }
}
