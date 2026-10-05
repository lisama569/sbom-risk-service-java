package com.github.lisama569.sbomriskservicejava.service;

import com.github.lisama569.sbomriskservicejava.model.IngestionResponse;
import com.github.lisama569.sbomriskservicejava.model.IngestionStatus;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.parser.CycloneDxBomParser;
import com.github.lisama569.sbomriskservicejava.parser.FormatDetector;
import com.github.lisama569.sbomriskservicejava.parser.SbomParser;
import com.github.lisama569.sbomriskservicejava.parser.SpdxBomParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 摄入服务：三态分类、文档内去重、重复提交幂等、并发串行化测试。 */
class SbomIngestServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SbomIngestServiceTest.class);

    private ComponentRepository repository;
    private SbomIngestService service;

    private static String cdx(String name, String version) {
        return "{\"bomFormat\":\"CycloneDX\",\"components\":[{\"name\":\""
                + name + "\",\"version\":\"" + version + "\"}]}";
    }

    private static final String CDX_TWO = """
            {"bomFormat":"CycloneDX","components":[
              {"name":"a-lib","version":"1.0.0"},
              {"name":"a-lib","version":"1.0.0"},
              {"name":"good-lib","version":"2.0.0"}
            ]}
            """;

    private static final String CDX_ONE_BAD = """
            {"bomFormat":"CycloneDX","components":[
              {"name":"ok-lib","version":"1.0.0"},
              {"name":"bad-lib","version":"not-semver"}
            ]}
            """;

    @BeforeEach
    void setUp() {
        repository = new ComponentRepository();
        List<SbomParser> parsers = List.of(new CycloneDxBomParser(), new SpdxBomParser());
        service = new SbomIngestService(repository, new FormatDetector(), parsers);
    }

    @Test
    @DisplayName("全部成功：状态 SUCCESS，accepted 计数正确")
    void successWhenAllValid() {
        IngestionResponse r = service.ingest("t-success", cdx("lib", "1.0.0"));
        log.info("输入摘要: target=t-success 单条合法组件 | 判定: status={}, accepted={}, rejected={}",
                r.status(), r.acceptedCount(), r.rejectedCount());
        assertEquals(IngestionStatus.SUCCESS, r.status());
        assertEquals(1, r.acceptedCount());
    }

    @Test
    @DisplayName("部分成功：坏条目不影响好条目，状态 PARTIAL_SUCCESS 且原因可区分")
    void partialSuccessIsolatesBadEntries() {
        IngestionResponse r = service.ingest("t-partial", CDX_ONE_BAD);
        log.info("输入摘要: 1 合法 + 1 非法版本 | 判定: status={}, accepted={}, rejected={}, reasons={}",
                r.status(), r.acceptedCount(), r.rejectedCount(),
                r.rejected().stream().map(x -> x.reason().name()).toList());
        assertEquals(IngestionStatus.PARTIAL_SUCCESS, r.status());
        assertEquals(1, r.acceptedCount());
        assertEquals(1, r.rejectedCount());
        assertEquals(RejectReason.MALFORMED_VERSION, r.rejected().get(0).reason());
        assertEquals(1, repository.findByTarget("t-partial").size());
    }

    @Test
    @DisplayName("文档内重复条目：第二份出现的重复被拒绝并给出 DUPLICATE_COMPONENT 原因")
    void duplicatesInsideOneDocumentAreRejected() {
        IngestionResponse r = service.ingest("t-dup-in-doc", CDX_TWO);
        log.info("输入摘要: 文档内 2 个相同条目 + 1 个其他 | 判定: status={}, accepted={}, rejected={}",
                r.status(), r.acceptedCount(), r.rejectedCount());
        assertEquals(2, r.acceptedCount());
        assertEquals(1, r.rejectedCount());
        assertEquals(RejectReason.DUPLICATE_COMPONENT, r.rejected().get(0).reason());
    }

    @Test
    @DisplayName("重复提交幂等：同清单二次提交 accepted=0、duplicate 全部，存储无重复记录")
    void repeatedSubmissionIsIdempotent() {
        String doc = cdx("lib", "1.0.0");
        IngestionResponse first = service.ingest("t-repeat", doc);
        IngestionResponse second = service.ingest("t-repeat", doc);
        log.info("输入摘要: 同一清单提交两次 | 第一次 accepted={} duplicate={}；第二次 accepted={} duplicate={}",
                first.acceptedCount(), first.duplicateCount(),
                second.acceptedCount(), second.duplicateCount());
        assertEquals(1, first.acceptedCount());
        assertEquals(0, first.duplicateCount());
        assertEquals(0, second.acceptedCount());
        assertEquals(1, second.duplicateCount());
        assertEquals(IngestionStatus.SUCCESS, second.status());
        assertEquals(1, repository.findByTarget("t-repeat").size());
    }

    @Test
    @DisplayName("整体失败：畸形文档状态 FAILED，不写入任何组件")
    void malformedDocumentFailsEntireIngestion() {
        IngestionResponse r = service.ingest("t-fail", "{not valid json");
        log.info("输入摘要: 畸形 JSON | 判定: status={}, reasons={}",
                r.status(), r.rejected().stream().map(x -> x.reason().name()).toList());
        assertEquals(IngestionStatus.FAILED, r.status());
        assertEquals(RejectReason.MALFORMED_DOCUMENT, r.rejected().get(0).reason());
        assertTrue(repository.findByTarget("t-fail").isEmpty());
    }

    @Test
    @DisplayName("并发提交：同一目标 N 线程同时提交，最终仅 1 条记录且 accepted+duplicate=N")
    void concurrentSubmissionsRemainIdempotent() throws InterruptedException {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger duplicate = new AtomicInteger();
        Set<IngestionStatus> statuses = ConcurrentHashMap.newKeySet();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    IngestionResponse r = service.ingest("t-concurrent", cdx("race-lib", "1.0.0"));
                    accepted.addAndGet(r.acceptedCount());
                    duplicate.addAndGet(r.duplicateCount());
                    statuses.add(r.status());
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("并发输入摘要: {} 个线程并发提交同一目标同一组件 | 汇总 accepted={}, duplicate={}, 存储={}",
                threads, accepted.get(), duplicate.get(),
                repository.findByTarget("t-concurrent").size());
        assertEquals(1, accepted.get(), "恰好一个请求把组件写入");
        assertEquals(threads - 1, duplicate.get(), "其余请求全部幂等命中");
        assertEquals(1, repository.findByTarget("t-concurrent").size());
        assertTrue(statuses.stream().allMatch(s -> s == IngestionStatus.SUCCESS));
    }

    @Test
    @DisplayName("并发提交不同组件：全部成功入库且无丢失")
    void concurrentDistinctComponentsAllAccepted() throws InterruptedException {
        int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    service.ingest("t-concurrent-distinct", cdx("lib-" + idx, "1.0.0"));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("并发不同组件输入摘要: {} 个线程提交不同组件 | 存储={}",
                threads, repository.findByTarget("t-concurrent-distinct").size());
        assertEquals(threads, repository.findByTarget("t-concurrent-distinct").size());
    }

    @Test
    @DisplayName("并发等价坐标写法：同一目标并发提交 purl 与 名字 两种写法，最终仅 1 条记录")
    void concurrentEquivalentSpellingsRemainIdempotent() throws InterruptedException {
        String viaPurl = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"log4j-core","version":"2.14.0",
                   "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"}]}
                """;
        String viaName = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"org.apache.logging.log4j:log4j-core","version":"2.14.0",
                   "ecosystems":["maven"]}]}
                """;
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger duplicate = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            final String doc = (i % 2 == 0) ? viaPurl : viaName;
            pool.submit(() -> {
                try {
                    start.await();
                    IngestionResponse r = service.ingest("t-equiv-race", doc);
                    accepted.addAndGet(r.acceptedCount());
                    duplicate.addAndGet(r.duplicateCount());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("并发等价写法输入摘要: {} 个线程交替提交 purl/名字 两种写法 | 汇总 accepted={}, duplicate={}, 存储={}",
                threads, accepted.get(), duplicate.get(),
                repository.findByTarget("t-equiv-race").size());
        assertEquals(1, accepted.get(), "等价写法归一到同一身份，恰好一个请求写入");
        assertEquals(threads - 1, duplicate.get(), "其余请求全部幂等命中");
        assertEquals(1, repository.findByTarget("t-equiv-race").size());
        assertEquals("maven::org.apache.logging.log4j:log4j-core@2.14.0",
                repository.findByTarget("t-equiv-race").get(0).key());
    }

    @Test
    @DisplayName("大清单重复提交：500 个组件两次提交，第二次全部幂等命中，存储条数不变")
    void largeManifestResubmissionIsIdempotent() {
        StringBuilder sb = new StringBuilder("{\"bomFormat\":\"CycloneDX\",\"components\":[");
        for (int i = 0; i < 500; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"name\":\"lib-").append(i).append("\",\"version\":\"1.0.0\",")
                    .append("\"purl\":\"pkg:npm/lib-").append(i).append("@1.0.0\"}");
        }
        sb.append("]}");
        String doc = sb.toString();
        IngestionResponse first = service.ingest("t-large", doc);
        IngestionResponse second = service.ingest("t-large", doc);
        log.info("大清单输入摘要: 500 个 npm 坐标组件提交两次 | 首次 accepted={} | 二次 accepted={} duplicate={} | 存储={}",
                first.acceptedCount(), second.acceptedCount(), second.duplicateCount(),
                repository.findByTarget("t-large").size());
        assertEquals(500, first.acceptedCount());
        assertEquals(0, second.acceptedCount());
        assertEquals(500, second.duplicateCount());
        assertEquals(IngestionStatus.SUCCESS, second.status());
        assertEquals(500, repository.findByTarget("t-large").size());
    }

    @Test
    @DisplayName("无法判定条目持久化且幂等：不支持坐标条目重复提交只留一条，报告目标存在")
    void unresolvedEntriesArePersistedAndIdempotent() {
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0"},
                  {"name":"ok-lib","version":"1.0.0","ecosystems":["maven"]}
                ]}
                """;
        IngestionResponse first = service.ingest("t-unresolved", doc);
        IngestionResponse second = service.ingest("t-unresolved", doc);
        log.info("输入摘要: pypi 不支持坐标 + maven 好组件提交两次 | 首次 unresolved={} | 二次 accepted={} duplicate={} unresolved={}",
                first.unresolvedCount(), second.acceptedCount(), second.duplicateCount(),
                second.unresolvedCount());
        assertEquals(1, first.unresolvedCount());
        assertEquals(IngestionStatus.PARTIAL_SUCCESS, first.status());
        assertEquals(0, second.unresolvedCount(), "UNKNOWN 条目同样幂等，不重复写入");
        assertEquals(1, repository.findUnresolved("t-unresolved").size());
        org.junit.jupiter.api.Assertions.assertTrue(repository.existsTarget("t-unresolved"));
    }

    @Test
    @DisplayName("全部条目无法判定的可解析文档：状态 PARTIAL_SUCCESS（207），UNKNOWN 仍进报告而非 404")
    void allUnrecognizedDocumentStillProducesUnknownReport() {
        String doc = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0"}
                ]}
                """;
        IngestionResponse r = service.ingest("t-all-unknown", doc);
        log.info("输入摘要: 唯一条目为 pypi 坐标 | 判定: status={} unresolved={}",
                r.status(), r.unresolvedCount());
        assertEquals(IngestionStatus.PARTIAL_SUCCESS, r.status());
        assertEquals(1, repository.findUnresolved("t-all-unknown").size());
    }

    @Test
    @DisplayName("并发等价写法（purl / 斜杠名字 / 全大写）：同一 Maven 库最终仅 1 条记录")
    void concurrentSlashAndCaseSpellingsRemainIdempotent() throws InterruptedException {
        String viaPurl = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"log4j-core","version":"2.14.0",
                   "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"}]}
                """;
        String viaSlash = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"org.apache.logging.log4j/log4j-core","version":"2.14.0",
                   "ecosystems":["maven"]}]}
                """;
        String viaUpper = """
                {"bomFormat":"CycloneDX","components":[
                  {"name":"ORG.APACHE.LOGGING.LOG4J/LOG4J-CORE","version":"2.14.0",
                   "ecosystems":["MAVEN"]}]}
                """;
        int threads = 15;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger duplicate = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            final String d = i % 3 == 0 ? viaPurl : (i % 3 == 1 ? viaSlash : viaUpper);
            pool.submit(() -> {
                try {
                    start.await();
                    IngestionResponse r = service.ingest("t-equiv-slash-race", d);
                    accepted.addAndGet(r.acceptedCount());
                    duplicate.addAndGet(r.duplicateCount());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("并发等价写法输入摘要: {} 个线程提交 purl/斜杠/大写 三种写法 | accepted={} duplicate={} 存储={}",
                threads, accepted.get(), duplicate.get(),
                repository.findByTarget("t-equiv-slash-race").size());
        assertEquals(1, accepted.get());
        assertEquals(threads - 1, duplicate.get());
        assertEquals(1, repository.findByTarget("t-equiv-slash-race").size());
        assertEquals("maven::org.apache.logging.log4j:log4j-core@2.14.0",
                repository.findByTarget("t-equiv-slash-race").get(0).key());
    }
}
