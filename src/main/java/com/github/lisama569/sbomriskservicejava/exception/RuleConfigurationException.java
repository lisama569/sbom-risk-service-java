package com.github.lisama569.sbomriskservicejava.exception;

/**
 * Raised when a locally maintained rule is syntactically invalid.
 */
public class RuleConfigurationException extends RuntimeException {

    public RuleConfigurationException(String message) {
        super(message);
    }

    public RuleConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
