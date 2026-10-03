package com.github.lisama569.sbomriskservicejava.service;

import com.github.lisama569.sbomriskservicejava.model.Component;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 组件身份归一：等价坐标写法、跨生态隔离、不支持/畸形坐标、规模并发幂等。 */
class ComponentIdentityIngestTest {

    private static final Logger log = LoggerFactory.getLogger(ComponentIdentityIngestTest.class);

    private ComponentRepository repository;
    private SbomIngestService service;

    @BeforeEach
    void setUp() {
        repository = new ComponentRepository();
        List<SbomParser> parsers = List.of(new CycloneDxBomParser(), new SpdxBomParser());
        service = new SbomIngestService(repository, new FormatDetector(), parsers);
    }

    private static String cdxEntry(String name, String version, String ecosystems, String purl) {
        StringBuilder sb = new StringBuilder("{\"bomFormat\":\"CycloneDX\",\"components\":[{");
        sb.append("\"version\":\"").append(version).append("\"");
        if (name != null) {
            sb.append(",\"name\":\"").append(name).append("\"");
        }
        if (ecosystems != null) {
            sb.append(",\"ecosystems\":[\"").append(ecosystems).append("\"]");
        }
        if (purl != null) {
            sb.append(",\"purl\":\"").append(purl).append("\"");
        }
        return sb.append("}]}").toString();
    }

    @Test
    @DisplayName("maven 等价写法归一：purl / 冒号名 / 斜杠名 / 大小写差异，四次提交仅 1 条记录")
    void mavenEquivalentWritingsDeduplicate() {
        String byPurl = cdxEntry("log4j-core（随意名）", "2.14.0", null,
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0");
        String byColonName = cdxEntry("org.apache.logging.log4j:log4j-core", "2.14.0", "maven", null);
        String bySlashName = cdxEntry("org.apache.logging.log4j/log4j-core", "2.14.0", "maven", null);
        String byUpperPurl = cdxEntry(null, "2.14.0", null,
                "pkg:maven/Org.Apache.Logging.Log4j/Log4j-Core@2.14.0");

        IngestionResponse r1 = service.ingest("t-mvn-eq", byPurl);
        IngestionResponse r2 = service.ingest("t-mvn-eq", byColonName);
        IngestionResponse r3 = service.ingest("t-mvn-eq", bySlashName);
        IngestionResponse r4 = service.ingest("t-mvn-eq", byUpperPurl);
        List<Component> stored = repository.findByTarget("t-mvn-eq");
        log.info("输入摘要: 同一 maven 组件的 4 种等价写法 | 各次 accepted={},{},{},{} duplicate={},{},{},{} | 存储={}",
                r1.acceptedCount(), r2.acceptedCount(), r3.acceptedCount(), r4.acceptedCount(),
                r1.duplicateCount(), r2.duplicateCount(), r3.duplicateCount(), r4.duplicateCount(),
                stored.stream().map(Component::key).toList());
        assertEquals(1, r1.acceptedCount());
        assertEquals(1, r2.duplicateCount());
        assertEquals(1, r3.duplicateCount());
        assertEquals(1, r4.duplicateCount());
        assertEquals(1, stored.size());
        assertEquals("maven::org.apache.logging.log4j:log4j-core@2.14.0", stored.get(0).key());
    }

    @Test
    @DisplayName("npm 作用域等价写法归一：%40 编码 purl 与 @scope/name 名称写法指向同一身份")
    void npmScopedEquivalentWritingsDeduplicate() {
        String byPurl = cdxEntry(null, "15.0.0", null, "pkg:npm/%40angular/core@15.0.0");
        String byName = cdxEntry("@angular/core", "15.0.0", "npm", null);

        IngestionResponse r1 = service.ingest("t-npm-eq", byPurl);
        IngestionResponse r2 = service.ingest("t-npm-eq", byName);
        List<Component> stored = repository.findByTarget("t-npm-eq");
        log.info("输入摘要: npm 作用域组件的 purl 与名称两种写法 | accepted={},{} duplicate={},{} | 存储={}",
                r1.acceptedCount(), r2.acceptedCount(), r1.duplicateCount(), r2.duplicateCount(),
                stored.stream().map(Component::key).toList());
        assertEquals(1, r1.acceptedCount());
        assertEquals(1, r2.duplicateCount());
        assertEquals(1, stored.size());
        assertEquals("npm::@angular/core@15.0.0", stored.get(0).key());
    }

    @Test
    @DisplayName("跨生态隔离：同名 lodash 在 npm 与 maven 下是两条不同记录，互不串号")
    void crossEcosystemNamesDoNotCollide() {
        String npmLodash = cdxEntry(null, "4.17.20", null, "pkg:npm/lodash@4.17.20");
        String mavenLodash = cdxEntry("lodash", "4.17.20", "maven", null);

        service.ingest("t-cross-eco", npmLodash);
        service.ingest("t-cross-eco", mavenLodash);
        List<Component> stored = repository.findByTarget("t-cross-eco");
        log.info("输入摘要: npm lodash 与 maven lodash 同名不同生态 | 存储={}",
                stored.stream().map(Component::key).toList());
        assertEquals(2, stored.size());
        assertTrue(stored.stream().anyMatch(c -> c.key().equals("npm::lodash@4.17.20")));
        assertTrue(stored.stream().anyMatch(c -> c.key().equals("maven::lodash@4.17.20")));
    }

    @Test
    @DisplayName("畸形 purl：条目被拒绝且原因 MALFORMED_PACKAGE_URL，不会混为普通名字入库")
    void malformedPurlIsRejectedDistinctly() {
        String doc = cdxEntry("perfectly-fine-name", "1.0.0", "maven", "not-a-purl");
        IngestionResponse r = service.ingest("t-bad-purl", doc);
        log.info("输入摘要: 名字合法但 purl 畸形 | 判定: status={}, rejected 原因={}",
                r.status(), r.rejected().stream().map(x -> x.reason().name()).toList());
        assertEquals(IngestionStatus.FAILED, r.status());
        assertEquals(RejectReason.MALFORMED_PACKAGE_URL, r.rejected().get(0).reason());
        assertTrue(repository.findByTarget("t-bad-purl").isEmpty());
    }

    @Test
    @DisplayName("不支持的坐标类型：保留通用身份入库（生态=purl 类型），不当普通名字处理")
    void unsupportedPurlTypeKeepsGenericIdentity() {
        String doc = cdxEntry(null, "3.0.0", null, "pkg:deb/debian/libssl3@3.0.0");
        IngestionResponse r = service.ingest("t-deb", doc);
        List<Component> stored = repository.findByTarget("t-deb");
        log.info("输入摘要: deb 坐标（暂不支持）| 判定: status={} | 存储={}",
                r.status(), stored.stream().map(Component::key).toList());
        assertEquals(IngestionStatus.SUCCESS, r.status());
        assertEquals(1, stored.size());
        assertEquals("deb", stored.get(0).ecosystem());
        assertEquals("deb::debian/libssl3@3.0.0", stored.get(0).key());
    }

    @Test
    @DisplayName("大清单 + 并发重复提交：300 组件 × 8 线程，存储恰好 300 条且 accepted 总和 300")
    void largeManifestConcurrentResubmissionStaysConsistent() throws InterruptedException {
        StringBuilder doc = new StringBuilder("{\"bomFormat\":\"CycloneDX\",\"components\":[");
        for (int i = 0; i < 300; i++) {
            if (i > 0) {
                doc.append(',');
            }
            doc.append("{\"name\":\"lib-").append(i)
                    .append("\",\"version\":\"1.0.0\",\"ecosystems\":[\"maven\"]}");
        }
        doc.append("]}");
        String content = doc.toString();

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger duplicate = new AtomicInteger();
        AtomicInteger errors = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    IngestionResponse r = service.ingest("t-large", content);
                    accepted.addAndGet(r.acceptedCount());
                    duplicate.addAndGet(r.duplicateCount());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    errors.incrementAndGet();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        int stored = repository.findByTarget("t-large").size();
        log.info("并发输入摘要: 300 组件大清单 × {} 线程重复提交 | 汇总 accepted={}, duplicate={}, 存储={}, 错误={}",
                threads, accepted.get(), duplicate.get(), stored, errors.get());
        assertEquals(0, errors.get());
        assertEquals(300, accepted.get(), "全部线程合计恰好 300 条新记录");
        assertEquals(300 * (threads - 1), duplicate.get(), "其余全部为幂等命中");
        assertEquals(300, stored, "存储无重复、无丢失");
    }
}
