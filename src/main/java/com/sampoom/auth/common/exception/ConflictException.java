package com.sampoom.auth.common.exception;

import com.sampoom.auth.common.response.ErrorStatus;
import org.springframework.http.HttpStatus;

public class ConflictException extends BaseException {
    public ConflictException() {
        super(HttpStatus.CONFLICT);
    }

    public ConflictException(String message) {
        super(HttpStatus.CONFLICT, message);
    }

    public ConflictException(ErrorStatus errorStatus) {
        super(errorStatus.getHttpStatus(), errorStatus.getMessage(), errorStatus.getCode());
    }
}
