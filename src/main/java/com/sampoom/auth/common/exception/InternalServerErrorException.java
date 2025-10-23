package com.sampoom.auth.common.exception;

import com.sampoom.auth.common.response.ErrorStatus;
import org.springframework.http.HttpStatus;

public class InternalServerErrorException extends BaseException {
    public InternalServerErrorException() {
        super(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    public InternalServerErrorException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }

    public InternalServerErrorException(ErrorStatus errorStatus) {
        super(errorStatus.getHttpStatus(), errorStatus.getMessage(), errorStatus.getCode());
    }
}
