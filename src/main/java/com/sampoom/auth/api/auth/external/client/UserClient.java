package com.sampoom.auth.api.auth.external.client;

import com.sampoom.auth.common.common.response.ApiResponse;
import com.sampoom.auth.api.auth.external.dto.UserResponse;
import com.sampoom.auth.api.auth.external.dto.VerifyLoginRequest;
import com.sampoom.auth.api.auth.external.fallback.UserClientFallback;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
        name = "user-service",
        url = "${user.service.url}",
        fallback = UserClientFallback.class
)
public interface UserClient {

    @PostMapping("/verify")
    ApiResponse<UserResponse> verifyLogin(@RequestBody VerifyLoginRequest verifyLoginRequest);
}