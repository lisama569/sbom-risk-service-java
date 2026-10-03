package com.github.lisama569.sbomriskservicejava.web;

import com.github.lisama569.sbomriskservicejava.model.IngestionResponse;
import com.github.lisama569.sbomriskservicejava.model.IngestionStatus;
import com.github.lisama569.sbomriskservicejava.model.RiskReport;
import com.github.lisama569.sbomriskservicejava.model.SbomFormat;
import com.github.lisama569.sbomriskservicejava.parser.SbomParseException;
import com.github.lisama569.sbomriskservicejava.service.RiskEvaluationService;
import com.github.lisama569.sbomriskservicejava.service.SbomIngestService;
import com.github.lisama569.sbomriskservicejava.web.dto.SbomSubmissionRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
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
     * 提交清单。传输层状态码即可区分三种结果（响应体细分信息保持不变）：
     * <ul>
     *   <li>{@code 200 OK}：全部成功（SUCCESS）；若本次为纯幂等重放
     *       （accepted=0 且 duplicate&gt;0），额外携带响应头
     *       {@code X-Idempotent-Replay: true}；</li>
     *   <li>{@code 207 Multi-Status}：部分成功（PARTIAL_SUCCESS）；</li>
     *   <li>{@code 422 Unprocessable Content}：整体失败（FAILED）。</li>
     * </ul>
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
        HttpStatusCode status = switch (response.status()) {
            case SUCCESS -> HttpStatus.OK;
            case PARTIAL_SUCCESS -> HttpStatus.MULTI_STATUS;
            case FAILED -> HttpStatusCode.valueOf(422);
        };
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(status);
        if (isIdempotentReplay(response)) {
            builder.header("X-Idempotent-Replay", "true");
        }
        return builder.body(response);
    }

    /** 纯幂等重放：本次没有新条目入库、没有拒绝，全部命中已有记录。 */
    private static boolean isIdempotentReplay(IngestionResponse response) {
        return response.status() == IngestionStatus.SUCCESS
                && response.acceptedCount() == 0
                && response.duplicateCount() > 0;
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
