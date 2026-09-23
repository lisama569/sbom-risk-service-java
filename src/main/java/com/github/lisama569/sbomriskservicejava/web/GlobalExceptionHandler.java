package com.github.lisama569.sbomriskservicejava.web;

import com.github.lisama569.sbomriskservicejava.exception.NotFoundException;
import com.github.lisama569.sbomriskservicejava.exception.RuleConfigurationException;
import com.github.lisama569.sbomriskservicejava.exception.SbomIngestionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps domain exceptions to distinguishable HTTP error responses.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(SbomIngestionException.class)
    public ResponseEntity<ErrorResponse> handleIngestion(SbomIngestionException ex) {
        log.info("document failure: reason={} detail={}", ex.reason(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse("ingestion_failed", ex.reason().name(), ex.getMessage(), null));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        log.info("document failure: reason=MALFORMED_PAYLOAD detail={}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse("ingestion_failed", "MALFORMED_PAYLOAD",
                        "request body is not valid JSON", null));
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(NotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse("not_found", "COMPONENT_NOT_FOUND", ex.getMessage(), null));
    }

    @ExceptionHandler(RuleConfigurationException.class)
    public ResponseEntity<ErrorResponse> handleRule(RuleConfigurationException ex) {
        log.info("rule rejection: reason=INVALID_RULE detail={}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse("invalid_rule", "INVALID_RULE", ex.getMessage(), null));
    }
}
