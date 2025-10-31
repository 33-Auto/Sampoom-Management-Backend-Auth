package com.sampoom.auth.api.auth.internal.client;

import com.sampoom.auth.api.auth.internal.config.InternalFeignConfig;
import com.sampoom.auth.api.auth.internal.dto.SignupUser;
import com.sampoom.auth.common.response.ApiResponse;
import com.sampoom.auth.api.auth.internal.fallback.UserClientFallback;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
        name = "user-service",
        url = "${user.service.url:http://user-service:8080}",
        fallback = UserClientFallback.class,
        configuration = InternalFeignConfig.class
)
public interface UserClient {
    @PostMapping("/internal/profile")
    ApiResponse<Void> createProfile(@RequestBody SignupUser req);
}