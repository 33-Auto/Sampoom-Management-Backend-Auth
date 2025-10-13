package com.sampoom.backend.auth.service;

import com.sampoom.backend.auth.external.dto.VerifyLoginRequest;
import com.sampoom.backend.auth.external.dto.UserResponse;
import com.sampoom.backend.auth.external.fallback.UserClientFallback;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@FeignClient(
        name = "user-service",
        url = "${user.service.url}", // application.yml에서 주입받음
        fallback = UserClientFallback.class // User 서비스 장애 대비용
)
public interface UserClient {

    @PostMapping("/user/verify-login")
    Boolean verifyLogin(@RequestBody VerifyLoginRequest request);

    @GetMapping("/users/email/{email}")
    UserResponse getUserByEmail(@PathVariable("email") String email);

    @GetMapping("/users/{id}")
    UserResponse getUserById(@PathVariable("id") Long id);
}
