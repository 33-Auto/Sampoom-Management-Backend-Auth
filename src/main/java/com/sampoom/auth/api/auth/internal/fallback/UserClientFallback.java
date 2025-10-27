package com.sampoom.auth.api.auth.internal.fallback;

import com.sampoom.auth.api.auth.internal.dto.UserProfile;
import com.sampoom.auth.common.response.ApiResponse;
import com.sampoom.auth.api.auth.internal.client.UserClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * User 서비스 장애(타임아웃, 500 등) 시 기본 동작 정의
 * - 보통은 null 반환하거나, 커스텀 예외를 던지도록 한다.
 */
@Component
public class UserClientFallback implements UserClient {
    @Override
    public ApiResponse<Void> createProfile(@RequestBody UserProfile req){
        return null;
    }
}
