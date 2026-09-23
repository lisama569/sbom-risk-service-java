package com.github.lisama569.sbomriskservicejava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end HTTP tests: status mapping, replay markers, risk verdicts and
 * rule administration with invalid-range rejection.
 */
@SpringBootTest
class SbomApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(SbomApiIntegrationTest.class);

    @Autowired
    private WebApplicationContext context;

    private final ObjectMapper mapper = new ObjectMapper();

    private MockMvc mvc() {
        return MockMvcBuilders.webAppContextSetup(context).build();
    }

    private String cdx(String serial, String components) {
        return "{\"bomFormat\":\"CycloneDX\",\"serialNumber\":\"" + serial
                + "\",\"components\":[" + components + "]}";
    }

    private String comp(String name, String version, String purl) {
        return "{\"type\":\"library\",\"name\":\"" + name + "\",\"version\":\"" + version + "\""
                + (purl != null ? ",\"purl\":\"" + purl + "\"" : "") + "}";
    }

    @Test
    void ingestAcceptedThenAssessVulnerableAndReplayIsMarked() throws Exception {
        String serial = "urn:uuid:it-accepted-" + System.nanoTime();
        String content = cdx(serial, comp("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"));
        String request = mapper.writeValueAsString(
                mapper.createObjectNode().put("documentId", serial).put("content", content));
        log.info("request summary: POST /sboms CycloneDX lodash@4.17.20");

        mvc().perform(post("/api/v1/sboms").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACCEPTED"))
                .andExpect(jsonPath("$.idempotentReplay").value(false))
                .andExpect(jsonPath("$.accepted[0].duplicate").value(false));

        MvcResult replay = mvc().perform(post("/api/v1/sboms").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.idempotentReplay").value(true))
                .andReturn();
        JsonNode replayBody = mapper.readTree(replay.getResponse().getContentAsString());
        log.info("response summary: replay status={}, duplicateFlag={}",
                replayBody.path("status").asText(),
                replayBody.path("accepted").get(0).path("duplicate").asBoolean());

        mvc().perform(get("/api/v1/components/risk?key=pkg:npm/lodash@4.17.20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict").value("VULNERABLE"))
                .andExpect(jsonPath("$.findings[0].ruleId").value("LOCAL-CVE-2024-0001"));
    }

    @Test
    void partialSuccessReturns207WithDistinguishableReasons() throws Exception {
        String serial = "urn:uuid:it-partial-" + System.nanoTime();
        String content = cdx(serial,
                comp("minimist", "1.2.5", "pkg:npm/minimist@1.2.5") + ","
                        + comp("broken", "not-semver", "pkg:npm/broken@not-semver"));
        String request = mapper.writeValueAsString(
                mapper.createObjectNode().put("documentId", serial).put("content", content));
        log.info("request summary: POST /sboms 2 entries (good + INVALID_VERSION)");

        mvc().perform(post("/api/v1/sboms").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isMultiStatus())
                .andExpect(jsonPath("$.status").value("PARTIAL"))
                .andExpect(jsonPath("$.accepted.length()").value(1))
                .andExpect(jsonPath("$.rejected[0].reason").value("INVALID_VERSION"));
    }

    @Test
    void malformedAndUnsupportedPayloadsAreClassifiedSeparately() throws Exception {
        log.info("request summary: POST /sboms with broken JSON");
        mvc().perform(post("/api/v1/sboms").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"content\":\"{broken\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("MALFORMED_PAYLOAD"));

        String request = mapper.writeValueAsString(mapper.createObjectNode()
                .put("content", "{\"unknown\":true,\"components\":[]}"));
        log.info("request summary: POST /sboms with unknown format markers");
        mvc().perform(post("/api/v1/sboms").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("UNSUPPORTED_FORMAT"));
    }

    @Test
    void invalidRuleRangeIsRejectedByAdminApi() throws Exception {
        String rule = """
                {"id":"LOCAL-TEST-BAD-RANGE","ecosystem":"npm","name":"x","range":">=banana","severity":"LOW"}
                """;
        log.info("request summary: POST /rules/vulnerabilities with invalid range '>=banana'");
        mvc().perform(post("/api/v1/rules/vulnerabilities").contentType(MediaType.APPLICATION_JSON).content(rule))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_RULE"));
    }

    @Test
    void newRuleMakesSubsequentAssessmentsReproduciblyChange() throws Exception {
        // add a rule at runtime, then the same component assesses deterministically twice
        String serial = "urn:uuid:it-rule-update-" + System.nanoTime();
        String content = cdx(serial, comp("brand-new-lib", "1.0.0", "pkg:npm/brand-new-lib@1.0.0"));
        String request = mapper.writeValueAsString(
                mapper.createObjectNode().put("documentId", serial).put("content", content));
        mvc().perform(post("/api/v1/sboms").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isOk());

        mvc().perform(get("/api/v1/components/risk?key=pkg:npm/brand-new-lib@1.0.0"))
                .andExpect(jsonPath("$.verdict").value("SAFE"));

        String rule = """
                {"id":"LOCAL-TEST-NEW","ecosystem":"npm","name":"brand-new-lib","range":"<2.0.0","severity":"HIGH"}
                """;
        mvc().perform(post("/api/v1/rules/vulnerabilities").contentType(MediaType.APPLICATION_JSON).content(rule))
                .andExpect(status().isOk());
        log.info("request summary: added LOCAL-TEST-NEW affecting brand-new-lib <2.0.0");

        MvcResult first = mvc().perform(get("/api/v1/components/risk?key=pkg:npm/brand-new-lib@1.0.0"))
                .andExpect(jsonPath("$.verdict").value("VULNERABLE"))
                .andReturn();
        MvcResult second = mvc().perform(get("/api/v1/components/risk?key=pkg:npm/brand-new-lib@1.0.0"))
                .andExpect(jsonPath("$.verdict").value("VULNERABLE"))
                .andReturn();
        log.info("response summary: after rule update both verdicts identical={}",
                first.getResponse().getContentAsString().equals(second.getResponse().getContentAsString()));
    }

    @Test
    void spdxFormatIsIngestedAndAssessed() throws Exception {
        String serial = "urn:spdx:it-" + System.nanoTime();
        String content = """
                {"spdxVersion":"SPDX-2.3","documentNamespace":"%s","packages":[
                  {"name":"log4j-core","versionInfo":"2.14.1",
                   "externalRefs":[{"referenceType":"purl",
                     "referenceLocator":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}
                ]}
                """.formatted(serial);
        String request = mapper.writeValueAsString(
                mapper.createObjectNode().put("documentId", serial).put("content", content));
        log.info("request summary: POST /sboms SPDX log4j-core@2.14.1");
        mvc().perform(post("/api/v1/sboms").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.format").value("SPDX_JSON"));
        mvc().perform(get("/api/v1/components/risk?key=pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"))
                .andExpect(jsonPath("$.verdict").value("VULNERABLE"))
                .andExpect(jsonPath("$.findings[0].ruleId").value("LOCAL-CVE-2023-0010"));
    }
}
