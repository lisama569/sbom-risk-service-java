package com.github.lisama569.sbomriskservicejava.web;

import com.github.lisama569.sbomriskservicejava.model.IngestionResponse;
import com.github.lisama569.sbomriskservicejava.model.RiskReport;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import com.github.lisama569.sbomriskservicejava.parser.SbomParseException;
import com.github.lisama569.sbomriskservicejava.service.RiskEvaluationService;
import com.github.lisama569.sbomriskservicejava.service.SbomIngestService;
import com.github.lisama569.sbomriskservicejava.web.dto.SbomSubmissionRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 清单摄入与风险判定 HTTP 接口。 */
@RestController
@RequestMapping("/api/sbom")
public class SbomController {

    private final SbomIngestService ingestService;
    private final RiskEvaluationService riskEvaluationService;

    public SbomController(SbomIngestService ingestService, RiskEvaluationService riskEvaluationService) {
        this.ingestService = ingestService;
        this.riskEvaluationService = riskEvaluationService;
    }

    /**
     * 提交清单。HTTP 状态始终为 200，整体失败/部分成功/成功由响应体 {@code status} 区分。
     */
    @PostMapping("/ingest")
    public ResponseEntity<IngestionResponse> ingest(@RequestBody SbomSubmissionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request body is required");
        }
        SbomFormat hint = null;
        if (request.format() != null && !request.format().isBlank()) {
            hint = parseFormatHint(request.format());
        }
        IngestionResponse response = ingestService.ingest(request.targetId(), request.content(), hint);
        return ResponseEntity.ok(response);
    }

    /** 查询某目标当前清单的风险判定报告。 */
    @GetMapping("/targets/{targetId}/report")
    public RiskReport report(@PathVariable String targetId) {
        return riskEvaluationService.evaluate(targetId);
    }

    private SbomFormat parseFormatHint(String hint) {
        return switch (hint.trim().toLowerCase()) {
            case "cyclonedx", "cyclonedx-json" -> SbomFormat.CYCLONEDX_JSON;
            case "spdx", "spdx-json" -> SbomFormat.SPDX_JSON;
            default -> throw new SbomParseException("unsupported format hint: " + hint);
        };
    }
}
