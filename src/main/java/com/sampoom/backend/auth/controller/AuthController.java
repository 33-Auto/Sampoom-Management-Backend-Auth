package com.sampoom.backend.auth.controller;

import com.sampoom.backend.auth.common.response.*;
import com.sampoom.backend.auth.controller.dto.request.LoginRequest;
import com.sampoom.backend.auth.controller.dto.request.RefreshRequest;
import com.sampoom.backend.auth.controller.dto.response.LoginResponse;
import com.sampoom.backend.auth.controller.dto.response.RefreshResponse;
import com.sampoom.backend.auth.jwt.JwtProvider;
import com.sampoom.backend.auth.service.AuthService;
import com.sampoom.backend.auth.service.RefreshTokenService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@Slf4j
@SecurityRequirement(name = "bearerAuth") // 기본적으로 AccessToken 필요
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshService;
    private final JwtProvider jwtProvider;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody LoginRequest req) {
        try {
            LoginResponse resp = authService.login(req);
            return ApiResponse.success(SuccessStatus.OK, resp);
        } catch (Exception e) {
            // ️ 제네릭 맞추기 위해 ApiResponse<Void>를 감싸는 ResponseEntity<ApiResponse<LoginResponse>> 불가 → 직접 생성
            ApiResponse<LoginResponse> response = ApiResponse.<LoginResponse>builder()
                    .status(ErrorStatus.UNAUTHORIZED.getStatusCode())
                    .success(false)
                    .message(e.getMessage())
                    .build();
            return ResponseEntity.status(ErrorStatus.UNAUTHORIZED.getStatusCode()).body(response);
        }
    }

@PostMapping("/refresh")
public ResponseEntity<ApiResponse<RefreshResponse>> refresh(@RequestBody RefreshRequest req) {
    try {
        // 그냥 토큰만 받아서 서비스로 넘긴다 (검증 X)
        RefreshResponse resp = authService.refresh(req.getRefreshToken());
        return ApiResponse.success(SuccessStatus.OK, resp);
    } catch (Exception e) {
        ApiResponse<RefreshResponse> response = ApiResponse.<RefreshResponse>builder()
                .status(ErrorStatus.UNAUTHORIZED.getStatusCode())
                .success(false)
                .message(e.getMessage())
                .build();
        return ResponseEntity.status(ErrorStatus.UNAUTHORIZED.getStatusCode()).body(response);
    }
}


    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(Authentication authentication) {
        try {
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.fail(401, "인증되지 않은 요청입니다."));
            }
            Long userId = Long.valueOf(authentication.getName());
            authService.logout(userId);
            return ApiResponse.success_only(SuccessStatus.OK);
        } catch (Exception e) {
            log.error("로그아웃 처리 중 오류 발생", e);
            return ResponseEntity.status(401)
                        .body(ApiResponse.fail(401, "로그아웃 처리에 실패했습니다."));
        }
    }
}
