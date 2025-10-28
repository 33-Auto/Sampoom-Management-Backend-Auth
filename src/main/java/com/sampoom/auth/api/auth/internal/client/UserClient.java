package com.sampoom.auth.api.auth.internal.client;

import com.sampoom.auth.api.auth.internal.dto.AuthUserProfile;
import com.sampoom.auth.common.response.ApiResponse;
import com.sampoom.auth.api.auth.internal.fallback.UserClientFallback;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
        name = "user-service",
        url = "${user.service.url}",
        fallback = UserClientFallback.class
)
public interface UserClient {
    @PostMapping("/profile")
    ApiResponse<Void> createProfile(@RequestBody AuthUserProfile req);
}