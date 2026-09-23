package com.github.lisama569.sbomriskservicejava.web.dto;

import java.util.List;

/** 统一错误响应体。 */
public record ErrorResponse(String error, String message, List<String> details) {

    public static ErrorResponse of(String error, String message) {
        return new ErrorResponse(error, message, List.of());
    }
}
