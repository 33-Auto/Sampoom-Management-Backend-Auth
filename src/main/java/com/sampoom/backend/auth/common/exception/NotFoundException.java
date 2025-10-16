package com.sampoom.backend.auth.common.exception;

import com.sampoom.backend.auth.common.response.ErrorStatus;
import org.springframework.http.HttpStatus;

public class NotFoundException extends BaseException {
  public NotFoundException() {
    super(HttpStatus.NOT_FOUND);
  }

  public NotFoundException(String message) {
    super(HttpStatus.NOT_FOUND, message);
  }

  public NotFoundException(ErrorStatus errorStatus) {
      super(errorStatus.getHttpStatus(), errorStatus.getMessage(), errorStatus.getCode());
  }
}
