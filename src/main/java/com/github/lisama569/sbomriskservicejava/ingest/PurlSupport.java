package com.github.lisama569.sbomriskservicejava.ingest;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Minimal parser for Package URLs (spec 7.x) used only to derive a stable
 * component identity. Qualifiers and subpaths are dropped; the percent-encoded
 * name and namespace are decoded.
 */
public final class PurlSupport {

    /**
     * @param purl candidate purl
     * @return canonical key {@code pkg:type/namespace/name@version} (without
     *         qualifiers/subpath), or null if the input is not a recognizable purl
     */
    public static ParsedPurl parse(String purl) {
        if (purl == null || purl.isBlank()) {
            return null;
        }
        String trimmed = purl.trim();
        if (!trimmed.startsWith("pkg:")) {
            return null;
        }
        String body = trimmed.substring(4);
        int hash = body.indexOf('#');
        if (hash >= 0) {
            body = body.substring(0, hash);
        }
        String version = null;
        int at = body.lastIndexOf('@');
        int slashAfterAt = body.indexOf('/', Math.max(at, 0));
        if (at >= 0 && (slashAfterAt < 0 || slashAfterAt > at)) {
            // '@' is part of the version slot only when after the last path segment
            int slash = body.lastIndexOf('/');
            if (at > slash) {
                int question = body.indexOf('?', at);
                String rawVersion = question >= 0 ? body.substring(at + 1, question) : body.substring(at + 1);
                body = (question >= 0 ? body.substring(0, question) : body.substring(0, at));
                version = decode(rawVersion);
            }
        }
        int question = body.indexOf('?');
        if (question >= 0) {
            body = body.substring(0, question);
        }
        while (body.endsWith("/")) {
            body = body.substring(0, body.length() - 1);
        }
        int slash = body.indexOf('/');
        if (slash < 0) {
            return null;
        }
        String type = body.substring(0, slash).trim().toLowerCase();
        String path = body.substring(slash + 1);
        if (type.isBlank() || path.isBlank()) {
            return null;
        }
        String namespace = null;
        String name = path;
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash >= 0) {
            namespace = decode(path.substring(0, lastSlash));
            name = decode(path.substring(lastSlash + 1));
        } else {
            name = decode(name);
        }
        if (name.isBlank()) {
            return null;
        }
        String canonical = "pkg:" + type + "/"
                + (namespace != null ? namespace + "/" : "")
                + name + (version != null ? "@" + version : "");
        return new ParsedPurl(type, namespace, name, version, canonical);
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private PurlSupport() {
    }

    /** Result of parsing a purl. */
    public record ParsedPurl(
            String type,
            String namespace,
            String name,
            String version,
            String canonical
    ) {
    }
}
