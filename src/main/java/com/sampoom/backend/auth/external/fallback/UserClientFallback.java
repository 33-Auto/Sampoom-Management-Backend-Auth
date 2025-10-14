package com.sampoom.backend.auth.external.fallback;

import com.sampoom.backend.auth.common.response.ApiResponse;
import com.sampoom.backend.auth.external.dto.UserResponse;
import com.sampoom.backend.auth.external.client.UserClient;
import org.springframework.stereotype.Component;

/**
 * User 서비스 장애(타임아웃, 500 등) 시 기본 동작 정의
 * - 보통은 null 반환하거나, 커스텀 예외를 던지도록 한다.
 */
@Component
public class UserClientFallback implements UserClient {

    @Override
    public ApiResponse<UserResponse> getUserByEmail(String email) {
        // fallback에서는 보통 null을 반환하고 서비스 단에서 예외 처리
        return null;
    }
}
