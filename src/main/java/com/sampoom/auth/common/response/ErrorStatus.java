package com.sampoom.auth.common.response;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public enum ErrorStatus {

    // 400 BAD_REQUEST
    EXPIRATION_NULL(HttpStatus.BAD_REQUEST,"누락(Null)된 만료날짜입니다.",10410),
    TOKEN_NULL_BLANK(HttpStatus.BAD_REQUEST,"Null 또는 공백인 토큰입니다.",10407),
    // 401 UNAUTHORIZED
    USER_PASSWORD_INVALID(HttpStatus.UNAUTHORIZED, "유효하지 않은 비밀번호입니다.",10402),
    TOKEN_INVALID(HttpStatus.UNAUTHORIZED,"유효하지 않은 토큰입니다.",10404),
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED,"만료된 토큰입니다.",10405),
    TOKEN_TYPE_INVALID(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰 타입입니다.",10406),
    USER_DEACTIVATED(HttpStatus.UNAUTHORIZED,"비활성화된 유저입니다.",10410),
    // 403 FORBIDDEN

    // 404 NOT_FOUND
    USER_BY_EMAIL_NOT_FOUND(HttpStatus.NOT_FOUND, "이메일로 해당 유저를 찾을 수 없습니다.",10401),
    // 409 CONFLICT
    // 409 CONFLICT
    USER_EMAIL_DUPLICATED(HttpStatus.CONFLICT, "이미 존재하는 유저의 이메일입니다.", 10400),

    // 500 INTERNAL_SERVER_ERROR
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "요청 처리 중 서버 측에 오류가 발생했습니다.", 10500)

    ;
    private final HttpStatus httpStatus;
    private final String message;
    private final int code;

    public int getStatusCode() {
        return this.httpStatus.value();
    }
}
