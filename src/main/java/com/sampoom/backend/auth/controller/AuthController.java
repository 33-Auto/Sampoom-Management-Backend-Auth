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
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
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

    @Value("${jwt.access-ttl-seconds}")
    private long accessTtlSeconds;

    @Value("${jwt.refresh-ttl-seconds}")
    private long refreshTtlSeconds;

    @PostMapping("/login")
    @SecurityRequirement(name = "none")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest req, HttpServletResponse response) {
        LoginResponse resp = authService.login(req);

        ResponseCookie accessCookie = ResponseCookie.from("ACCESS_TOKEN", resp.getAccessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(accessTtlSeconds)
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("REFRESH_TOKEN", resp.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")           // 배포할 땐 "Strict"
                .maxAge(refreshTtlSeconds)  // 2주
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        return ApiResponse.success(SuccessStatus.OK,resp);
    }

    @PostMapping("/refresh")
    @SecurityRequirement(name = "none")
    public ResponseEntity<ApiResponse<Void>> refresh(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String refreshToken = null;

        // 쿠키에서 Refresh Token 읽기
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("REFRESH_TOKEN".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        RefreshResponse resp = authService.refresh(refreshToken);

        // 새 AccessToken 쿠키
        ResponseCookie accessCookie = ResponseCookie.from("ACCESS_TOKEN", resp.getAccessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Strict")
                .maxAge(resp.getExpiresIn())
                .build();

        // 새 RefreshToken 쿠키
        ResponseCookie refreshCookie = ResponseCookie.from("REFRESH_TOKEN", resp.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("Strict")
                .maxAge(1209600)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        return ApiResponse.success_only(SuccessStatus.OK);
    }


    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            Authentication authentication,
            HttpServletResponse response
    ) {
        Long userId = Long.valueOf(authentication.getName());
        authService.logout(userId);

        // 쿠키 삭제 (Max-Age=0)
        ResponseCookie deleteAccess = ResponseCookie.from("ACCESS_TOKEN", "")
                .path("/")
                .maxAge(0)
                .build();

        ResponseCookie deleteRefresh = ResponseCookie.from("REFRESH_TOKEN", "")
                .path("/")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteAccess.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, deleteRefresh.toString());

        return ApiResponse.success_only(SuccessStatus.OK);
    }
}
