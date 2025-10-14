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
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@SecurityRequirement(name = "bearerAuth") // 기본적으로 AccessToken 필요
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    @SecurityRequirement(name = "none")
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
@SecurityRequirement(name = "none")
public ResponseEntity<ApiResponse<RefreshResponse>> refresh(@Valid @RequestBody RefreshRequest req) {
    try {
        RefreshResponse resp = authService.refresh(req.getRefreshToken());
        return ApiResponse.success(SuccessStatus.OK, resp);
    } catch (ResponseStatusException e) {
        // AuthService에서 발생한 인증 관련 예외
        ApiResponse<RefreshResponse> response = ApiResponse.<RefreshResponse>builder()
                .status(e.getStatusCode().value())
                .success(false)
                .message(e.getReason())
                .build();
        return ResponseEntity.status(e.getStatusCode()).body(response);
    } catch (Exception e) {
        log.error("토큰 재발급 중 예외 발생", e);
        ApiResponse<RefreshResponse> response = ApiResponse.<RefreshResponse>builder()
            .status(500)
            .success(false).message("서버 오류가 발생했습니다")
            .build();
        return ResponseEntity.status(500).body(response);
    }
}


    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(Authentication authentication) {
        System.out.println("🔥 인증 객체: " + authentication);
        if (authentication != null) {
            System.out.println("🔥 Principal: " + authentication.getPrincipal());
            System.out.println("🔥 Authorities: " + authentication.getAuthorities());
        }
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
