package com.sampoom.backend.auth.controller;

import com.sampoom.backend.auth.common.response.*;
import com.sampoom.backend.auth.controller.dto.*;
import com.sampoom.backend.auth.controller.dto.request.LoginRequest;
import com.sampoom.backend.auth.controller.dto.request.RefreshRequest;
import com.sampoom.backend.auth.controller.dto.response.LoginResponse;
import com.sampoom.backend.auth.controller.dto.response.RefreshResponse;
import com.sampoom.backend.auth.service.AuthService;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody LoginRequest req) {
        try {
            LoginResponse resp = authService.login(req);
            return ApiResponse.success(SuccessStatus.OK, resp);
        } catch (Exception e) {
            // ⚠️ 제네릭 맞추기 위해 ApiResponse<Void>를 감싸는 ResponseEntity<ApiResponse<LoginResponse>> 불가 → 직접 생성
            ApiResponse<LoginResponse> response = ApiResponse.<LoginResponse>builder()
                    .status(ErrorStatus.UNAUTHORIZED.getStatusCode())
                    .success(false)
                    .message(ErrorStatus.UNAUTHORIZED.getMessage())
                    .build();
            return ResponseEntity.status(ErrorStatus.UNAUTHORIZED.getStatusCode()).body(response);
        }
    }
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<RefreshResponse>> refresh(@RequestBody RefreshRequest req) {
        try {
            RefreshResponse resp = authService.refresh(req.getRefreshToken());
            return ApiResponse.success(SuccessStatus.OK, resp);
        } catch (Exception e) {
            ApiResponse<RefreshResponse> response = ApiResponse.<RefreshResponse>builder()
                    .status(ErrorStatus.UNAUTHORIZED.getStatusCode())
                    .success(false)
                    .message(ErrorStatus.UNAUTHORIZED.getMessage())
                    .build();
            return ResponseEntity.status(ErrorStatus.UNAUTHORIZED.getStatusCode()).body(response);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String auth) {
        String token = auth.substring(7);
        Long userId = Long.valueOf(Jwts.parserBuilder().build()
                .parseClaimsJws(token).getBody().getSubject());
        authService.logout(userId);
        return ApiResponse.success_only(SuccessStatus.OK);
    }
}
