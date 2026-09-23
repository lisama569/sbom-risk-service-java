package com.github.lisama569.sbomriskservicejava.exception;

import com.github.lisama569.sbomriskservicejava.model.RejectReason;

/**
 * Document-level ingestion failure. Nothing is ingested when this is thrown.
 */
public class SbomIngestionException extends RuntimeException {

    private final RejectReason reason;

    public SbomIngestionException(RejectReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public SbomIngestionException(RejectReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public RejectReason reason() {
        return reason;
    }
}
