package com.sampoom.backend.auth.controller;

import com.sampoom.backend.auth.common.response.*;
import com.sampoom.backend.auth.controller.dto.request.LoginRequest;
import com.sampoom.backend.auth.controller.dto.request.RefreshRequest;
import com.sampoom.backend.auth.controller.dto.response.LoginResponse;
import com.sampoom.backend.auth.controller.dto.response.RefreshResponse;
import com.sampoom.backend.auth.jwt.JwtProvider;
import com.sampoom.backend.auth.service.AuthService;
import com.sampoom.backend.auth.service.RefreshTokenService;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@SecurityRequirement(name = "bearerAuth") // 기본적으로 AccessToken 필요
@RestController
@RequestMapping("/auth")
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
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(401)
                        .body(ApiResponse.fail(401, "토큰이 제공되지 않았습니다."));
            }
            String token = authHeader.substring(7); // Bearer(공백)
            Claims claims = jwtProvider.parse(token);
            Long userId = Long.valueOf(claims.getSubject());
            authService.logout(userId);
            return ApiResponse.success_only(SuccessStatus.OK);
        } catch (Exception e) {
            return ResponseEntity.status(403)
                    .body(ApiResponse.fail(403, "권한이 없습니다."));
        }
    }
}
