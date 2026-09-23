package com.github.lisama569.sbomriskservicejava.web;

import com.github.lisama569.sbomriskservicejava.service.TargetNotFoundException;
import com.github.lisama569.sbomriskservicejava.web.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 统一异常归类：
 * <ul>
 *   <li>非法参数 / 请求体不可读 → 400；</li>
 *   <li>目标不存在 → 404；</li>
 *   <li>其余未预期异常 → 500。</li>
 * </ul>
 * 注意：清单条目级失败不会走这里，而是在 200 响应体中以 PARTIAL_SUCCESS 表达。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException e) {
        return ResponseEntity.badRequest()
                .body(ErrorResponse.of("INVALID_REQUEST", e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest()
                .body(ErrorResponse.of("INVALID_REQUEST", "request body is missing or unreadable"));
    }

    @ExceptionHandler(TargetNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleTargetNotFound(TargetNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ErrorResponse.of("TARGET_NOT_FOUND", e.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of("INTERNAL_ERROR", e.getClass().getSimpleName() + ": " + e.getMessage()));
    }
}
