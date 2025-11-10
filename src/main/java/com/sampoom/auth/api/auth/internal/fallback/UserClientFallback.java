package com.sampoom.auth.api.auth.internal.fallback;

import com.sampoom.auth.api.auth.internal.dto.SignupUser;
import com.sampoom.auth.common.exception.InternalServerErrorException;
import com.sampoom.auth.api.auth.internal.client.UserClient;
import com.sampoom.auth.common.response.ErrorStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestBody;

@Slf4j
@Component
public class UserClientFallback implements UserClient {
    @Override
    public void createProfile(@RequestBody SignupUser req) {
        log.error("UserClientFallback] User 서비스 호출 실패. 요청 데이터: {}", req);
        throw new InternalServerErrorException(ErrorStatus.INTERNAL_SERVER_ERROR);
    }
}