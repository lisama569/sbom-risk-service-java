package com.github.lisama569.sbomriskservicejava.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** HTTP 全链路：摄入三态、报告复现、404、幂等并发。 */
@SpringBootTest
@AutoConfigureMockMvc
class SbomControllerIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(SbomControllerIntegrationTest.class);

    @Autowired
    private MockMvc mockMvc;

    private static String request(String targetId, String format, String content) {
        String body = content.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "");
        return "{\"targetId\":\"" + targetId + "\",\"format\":"
                + (format == null ? "null" : "\"" + format + "\"")
                + ",\"content\":\"" + body + "\"}";
    }

    private static final String CDX_VALID = """
            {"bomFormat":"CycloneDX","components":[
              {"name":"org.apache.logging.log4j:log4j-core","version":"2.14.0",
               "ecosystems":["maven"]}
            ]}
            """;

    private static final String SPDX_VALID = """
            {"spdxVersion":"SPDX-2.3","packages":[
              {"name":"lodash","versionInfo":"4.17.20",
               "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lodash@4.17.20"}]}
            ]}
            """;

    @Test
    @DisplayName("CycloneDX 全成功摄入 -> SUCCESS，报告 VULNERABLE 且结论含规则依据")
    void ingestCycloneDxAndReport() throws Exception {
        mockMvc.perform(post("/api/sbom/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request("http-cdx", null, CDX_VALID)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SUCCESS"))
                .andExpect(jsonPath("$.acceptedCount").value(1));
        log.info("HTTP 输入摘要: target=http-cdx CycloneDX 1 组件（log4j 2.14.0）");

        mockMvc.perform(get("/api/sbom/targets/http-cdx/report"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.overallLevel").value("VULNERABLE"))
                .andExpect(jsonPath("$.components[0].reasons[0]").value(
                        org.hamcrest.Matchers.containsString("CVE-2021-44228")))
                .andExpect(jsonPath("$.rulesVersion").isNotEmpty());
    }

    @Test
    @DisplayName("SPDX 显式格式摄入成功，生态由 purl 归一为 npm，lodash 4.17.20 命中 CVE")
    void ingestSpdxWithExplicitFormat() throws Exception {
        mockMvc.perform(post("/api/sbom/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request("http-spdx", "spdx", SPDX_VALID)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SUCCESS"));
        mockMvc.perform(get("/api/sbom/targets/http-spdx/report"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.overallLevel").value("VULNERABLE"))
                .andExpect(jsonPath("$.components[0].reasons[0]").value(
                        org.hamcrest.Matchers.containsString("CVE-2020-9999")));
        log.info("HTTP 输入摘要: target=http-spdx SPDX lodash 4.17.20 (purl=>npm)");
    }

    @Test
    @DisplayName("部分成功：HTTP 200 + PARTIAL_SUCCESS，拒绝原因逐条可区分")
    void partialSuccessReturnedWithDistinguishableReasons() throws Exception {
        String doc = "{\"bomFormat\":\"CycloneDX\",\"components\":["
                + "{\"name\":\"ok\",\"version\":\"1.0.0\"},"
                + "{\"name\":\"no-version\"},"
                + "{\"version\":\"1.0.0\"}]}";
        mockMvc.perform(post("/api/sbom/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request("http-partial", null, doc)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PARTIAL_SUCCESS"))
                .andExpect(jsonPath("$.acceptedCount").value(1))
                .andExpect(jsonPath("$.rejected[0].reason").value("MISSING_COMPONENT_VERSION"))
                .andExpect(jsonPath("$.rejected[1].reason").value("MISSING_COMPONENT_NAME"));
        log.info("HTTP 输入摘要: 1 合法 + 缺版本 + 缺名，响应 PARTIAL_SUCCESS 且 HTTP 200");
    }

    @Test
    @DisplayName("畸形文档：HTTP 200 + status=FAILED + MALFORMED_DOCUMENT，报告随后 404")
    void malformedDocumentFailsAndTargetAbsent() throws Exception {
        mockMvc.perform(post("/api/sbom/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request("http-malformed", null, "{broken")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("FAILED"))
                .andExpect(jsonPath("$.rejected[0].reason").value("MALFORMED_DOCUMENT"));
        mockMvc.perform(get("/api/sbom/targets/http-malformed/report"))
                .andExpect(status().isNotFound());
        log.info("HTTP 输入摘要: 畸形 JSON，整体失败不建目标，报告 404");
    }

    @Test
    @DisplayName("请求体非法 JSON -> 400 INVALID_REQUEST")
    void invalidHttpRequestIs400() throws Exception {
        mockMvc.perform(post("/api/sbom/ingest")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_REQUEST"));
    }

    @Test
    @DisplayName("HTTP 并发重复提交：仅 1 个 accepted，其余 duplicate，最终存储 1 条")
    void concurrentHttpIngestIsIdempotent() throws Exception {
        int threads = 10;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger errors = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    mockMvc.perform(post("/api/sbom/ingest")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(request("http-race", null, CDX_VALID)))
                            .andExpect(status().isOk());
                } catch (Exception e) {
                    errors.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        org.junit.jupiter.api.Assertions.assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));
        org.junit.jupiter.api.Assertions.assertEquals(0, errors.get());
        log.info("HTTP 并发输入摘要: {} 个请求并发提交同一目标，无错误，最终组件仅 1 条", threads);

        mockMvc.perform(get("/api/sbom/targets/http-race/report"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.components.length()").value(1));
    }
}
