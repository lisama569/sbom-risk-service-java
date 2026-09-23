package com.github.lisama569.sbomriskservicejava.service;

import com.github.lisama569.sbomriskservicejava.model.Component;
import com.github.lisama569.sbomriskservicejava.model.IngestionResponse;
import com.github.lisama569.sbomriskservicejava.model.IngestionStatus;
import com.github.lisama569.sbomriskservicejava.model.RejectReason;
import com.github.lisama569.sbomriskservicejava.model.RejectedItem;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import com.github.lisama569.sbomriskservicejava.parser.FormatDetector;
import com.github.lisama569.sbomriskservicejava.parser.ParseResult;
import com.github.lisama569.sbomriskservicejava.parser.SbomParseException;
import com.github.lisama569.sbomriskservicejava.parser.SbomParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 清单摄入服务。
 * <p>语义：
 * <ul>
 *   <li>文档级畸形（非法 JSON、缺少 components/packages 等）→ {@link IngestionStatus#FAILED}，
 *       整个请求不入库；</li>
 *   <li>部分条目缺名/缺版本/版本非法/文档内重复 → 逐条记录拒绝原因，其余条目照常入库，
 *       状态为 {@link IngestionStatus#PARTIAL_SUCCESS}；</li>
 *   <li>同一目标用锁串行化：并发提交被串行处理，已存在的组件计 duplicate，不产生重复记录，
 *       整份清单重复提交表现为幂等（accepted=0、duplicate=全部）；</li>
 *   <li>全部条目入库成功为 {@link IngestionStatus#SUCCESS}。</li>
 * </ul>
 */
@Service
public class SbomIngestService {

    private static final Logger log = LoggerFactory.getLogger(SbomIngestService.class);

    private final ComponentRepository componentRepository;
    private final FormatDetector formatDetector;
    private final List<SbomParser> parsers;

    public SbomIngestService(ComponentRepository componentRepository,
                             FormatDetector formatDetector,
                             List<SbomParser> parsers) {
        this.componentRepository = componentRepository;
        this.formatDetector = formatDetector;
        this.parsers = parsers;
    }

    /**
     * 摄入一份清单（自动识别格式）。
     *
     * @param targetId   目标编号（幂等域）
     * @param rawContent 清单原文
     * @return FAILED / PARTIAL_SUCCESS / SUCCESS 三态响应
     */
    public IngestionResponse ingest(String targetId, String rawContent) {
        return ingest(targetId, rawContent, null);
    }

    /**
     * 摄入一份清单。
     *
     * @param targetId   目标编号（幂等域）
     * @param rawContent 清单原文
     * @param formatHint 可空的显式格式提示；为 null 时自动识别
     * @return FAILED / PARTIAL_SUCCESS / SUCCESS 三态响应
     */
    public IngestionResponse ingest(String targetId, String rawContent, SbomFormat formatHint) {
        if (targetId == null || targetId.isBlank()) {
            throw new IllegalArgumentException("targetId must not be blank");
        }
        String content = rawContent == null ? "" : rawContent;
        log.info("SBOM ingest start | targetId={} | formatHint={} | bytes={} | head={}",
                targetId, formatHint == null ? "auto" : formatHint, content.length(),
                abbreviate(content));

        SbomFormat format;
        ParseResult parsed;
        try {
            format = formatHint != null ? formatHint : formatDetector.detect(content);
            SbomParser parser = parserFor(format);
            parsed = parser.parse(content);
        } catch (SbomParseException e) {
            log.warn("SBOM ingest failed (document level) | targetId={} | reason={}",
                    targetId, e.getMessage());
            List<RejectedItem> rejected = List.of(
                    new RejectedItem(-1, RejectReason.MALFORMED_DOCUMENT, e.getMessage()));
            return new IngestionResponse(targetId, IngestionStatus.FAILED, 0, 1, 0,
                    List.of(), rejected,
                    "ingestion failed: malformed or unrecognized document");
        }

        int parsedCount = parsed.components().size() + parsed.rejected().size();
        log.info("SBOM parsed | targetId={} | format={} | entries={} | acceptedByParser={} | rejectedByParser={}",
                targetId, format, parsedCount, parsed.components().size(), parsed.rejected().size());

        // 同一目标串行化，保证并发提交下幂等
        synchronized (componentRepository.lockFor(targetId)) {
            List<RejectedItem> rejected = new ArrayList<>(parsed.rejected());
            List<String> components = new ArrayList<>();
            Set<String> seenInThisSubmission = new HashSet<>();
            int duplicateCount = 0;

            // 保留解析顺序作为拒绝下标的语义，逐条处理，失败互不影响
            int newlyAccepted = 0;
            for (Component c : parsed.components()) {
                if (!seenInThisSubmission.add(c.key())) {
                    rejected.add(new RejectedItem(-1, RejectReason.DUPLICATE_COMPONENT,
                            "duplicate component within the same document: " + c.key()));
                    continue;
                }
                Optional<Component> existing = componentRepository.putIfAbsent(targetId, c);
                components.add(c.key());
                if (existing.isPresent()) {
                    duplicateCount++;
                } else {
                    newlyAccepted++;
                }
            }

            int rejectedCount = rejected.size();
            IngestionStatus status;
            if (newlyAccepted == 0 && duplicateCount == 0) {
                // 没有任何条目落库：文档级解析能通过但条目全部非法，或重复文档内条目
                status = IngestionStatus.FAILED;
            } else if (rejectedCount > 0) {
                status = IngestionStatus.PARTIAL_SUCCESS;
            } else {
                status = IngestionStatus.SUCCESS;
            }

            List<String> stored = componentRepository.findByTarget(targetId)
                    .stream().map(Component::key).sorted().toList();
            String summary = String.format(
                    "parsed=%d, newlyAccepted=%d, duplicates=%d, rejected=%d, storedForTarget=%d",
                    parsedCount, newlyAccepted, duplicateCount, rejectedCount, stored.size());
            log.info("SBOM ingest result | targetId={} | status={} | {}", targetId, status, summary);

            return new IngestionResponse(targetId, status, newlyAccepted, rejectedCount,
                    duplicateCount, List.copyOf(components), List.copyOf(rejected), summary);
        }
    }

    private SbomParser parserFor(SbomFormat format) {
        return parsers.stream()
                .filter(p -> p.supports(format))
                .findFirst()
                .orElseThrow(() -> new SbomParseException("no parser for format: " + format));
    }

    private static String abbreviate(String text) {
        String oneLine = text.replaceAll("\\s+", " ").trim();
        if (oneLine.length() <= 120) {
            return oneLine;
        }
        return oneLine.substring(0, 120) + "...";
    }
}
