package com.sampoom.auth.common.response;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public enum ErrorStatus {

    // 400 BAD_REQUEST
    NULL_EXPIRATION(HttpStatus.BAD_REQUEST, "누락(Null)된 만료날짜입니다.", 12403),
    NULL_TOKEN(HttpStatus.BAD_REQUEST,"토큰 값은 Null이면 안됩니다.",12401),
    BLANK_TOKEN(HttpStatus.BAD_REQUEST,"토큰 값은 공백이면 안됩니다.",12400),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "요청의 형식, 타입, 파라미터 등이 맞지 않습니다.",11400),
    INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST,"요청의 파라미터 입력 값이 유효하지 않습니다.",11402),
    INVALID_WORKSPACE_TYPE(HttpStatus.BAD_REQUEST, "유효하지 않은 조직(workspace) 타입입니다.", 11401),
    INVALID_EMPSTATUS_TYPE(HttpStatus.BAD_REQUEST,"유효하지 않은 직원 상태(EmployeeStatus) 타입입니다.",11404),

    // 401 UNAUTHORIZED
    INVALID_USER_PASSWORD(HttpStatus.UNAUTHORIZED, "유효하지 않은 비밀번호입니다.",11410),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다.", 12410),
    EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "만료된 토큰입니다.", 12411),
    INVALID_TOKEN_TYPE(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰 타입입니다.", 12412),
    DEACTIVATED_USER(HttpStatus.UNAUTHORIZED, "비활성화된 유저입니다.(LEAVE/RETIRED)", 11411),

    // 403 FORBIDDEN

    // 404 NOT_FOUND
    NOT_FOUND_USER_BY_ID(HttpStatus.NOT_FOUND, "유저 고유 번호(userId)로 해당 유저를 찾을 수 없습니다.", 11440),
    NOT_FOUND_USER_BY_EMAIL(HttpStatus.NOT_FOUND, "이메일로 해당 유저를 찾을 수 없습니다.", 11442),
    NOT_FOUND_USER_BY_WORKSPACE(HttpStatus.NOT_FOUND,"해당 조직 내에서 유저를 찾을 수 없습니다.",11441),
    // 409 CONFLICT
    DUPLICATED_USER_EMAIL(HttpStatus.CONFLICT, "이미 존재하는 유저의 이메일입니다.", 11490),

    // 500 INTERNAL_SERVER_ERROR
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부 오류가 발생했습니다.", 10500),
    FAILED_CONNECTION(HttpStatus.INTERNAL_SERVER_ERROR,"요청이 서버 측에 전달조차 되지 않았습니다.",10502),
    OUTBOX_SERIALIZATION_ERROR(HttpStatus.INTERNAL_SERVER_ERROR,"Outbox 직렬화에 실패했습니다.",10505),
    INVALID_EVENT_FORMAT(HttpStatus.INTERNAL_SERVER_ERROR, "이벤트 형식이 유효하지 않습니다.", 10501),
    FAILED_CONNECTION_KAFKA(HttpStatus.INTERNAL_SERVER_ERROR,"Kafka 브로커 연결 또는 통신에 실패했습니다.",10503),
    EVENT_PROCESSING_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "Kafka 이벤트 처리 중 예외가 발생했습니다.",10504),

    ;

    private final HttpStatus httpStatus;
    private final String message;
    private final int code;

    public int getStatusCode() {
        return this.httpStatus.value();
    }
}