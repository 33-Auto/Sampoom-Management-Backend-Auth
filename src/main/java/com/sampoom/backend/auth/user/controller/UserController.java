package com.sampoom.backend.auth.user.controller;

import com.sampoom.backend.auth.common.response.ApiResponse;
import com.sampoom.backend.auth.common.response.SuccessStatus;
import com.sampoom.backend.auth.user.controller.dto.request.SignupRequest;
import com.sampoom.backend.auth.user.controller.dto.response.SignupResponse;
import com.sampoom.backend.auth.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<SignupResponse>> signup(@RequestBody SignupRequest req) {
        SignupResponse resp = userService.signup(req);
        return ApiResponse.success(SuccessStatus.CREATED, resp);
    }
}
