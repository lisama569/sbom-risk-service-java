package com.github.lisama569.sbomriskservicejava.exception;

/**
 * Raised when a queried component or rule does not exist.
 */
public class NotFoundException extends RuntimeException {

    public NotFoundException(String message) {
        super(message);
    }
}
