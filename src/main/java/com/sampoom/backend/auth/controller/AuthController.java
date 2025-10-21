package com.sampoom.backend.auth.controller;

import com.sampoom.backend.auth.common.exception.UnauthorizedException;
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
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Value("${jwt.access-ttl-seconds}")
    private long accessTtlSeconds;

    @Value("${jwt.refresh-ttl-seconds}")
    private long refreshTtlSeconds;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest req,
            HttpServletResponse response,
            @RequestHeader(value = "X-Client-Type", defaultValue = "APP") String clientType) {

        LoginResponse resp = authService.login(req);

        if ("WEB".equalsIgnoreCase(clientType)) {
            // 쿠키 세팅
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
                    .sameSite("None")
                    .maxAge(refreshTtlSeconds)
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
            response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

            // WEB: body에 토큰 제외
            LoginResponse webResp = LoginResponse.builder()
                    .userId(resp.getUserId())
                    .userName(resp.getUserName())
                    .role(resp.getRole())
                    .expiresIn(resp.getExpiresIn())
                    .build();

            return ApiResponse.success(SuccessStatus.OK, webResp);
        }

        // APP: body에 토큰 포함
        return ApiResponse.success(SuccessStatus.OK, resp);
    }


    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<RefreshResponse>> refresh(
            @RequestBody(required = false) RefreshRequest refreshRequest,
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(value = "X-Client-Type", defaultValue = "APP") String clientType
    ) {
        String refreshToken = null;
        // WEB: 쿠키에서 리프레시 토큰 추출
        if ("WEB".equalsIgnoreCase(clientType)) {
            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if ("REFRESH_TOKEN".equals(cookie.getName())) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }
        }
        // APP: 헤더에서 리프레시 토큰 추출
        else if ("APP".equalsIgnoreCase(clientType)) {
            if (refreshRequest != null) {
                refreshToken = refreshRequest.getRefreshToken();
            }
        }

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
        }

        RefreshResponse resp = authService.refresh(refreshToken);

        if ("WEB".equalsIgnoreCase(clientType)) {
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
                    .sameSite("None")
                    .maxAge(refreshTtlSeconds)
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
            response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        }
        return ApiResponse.success(SuccessStatus.OK,resp);
    }


    @PostMapping("/logout")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse<Void>> logout(
            Authentication authentication,
            HttpServletResponse response,
            @RequestHeader(value = "X-Client-Type", defaultValue = "APP") String clientType
    ) {
        Long userId = Long.valueOf(authentication.getName());

        // WEB: 쿠키 삭제
        if ("WEB".equalsIgnoreCase(clientType)) {
            ResponseCookie accessCookie = ResponseCookie.from("ACCESS_TOKEN", "")
                    .path("/")
                    .maxAge(0)
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
            ResponseCookie refreshCookie = ResponseCookie.from("REFRESH_TOKEN", "")
                    .path("/")
                    .maxAge(0)
                    .build();
            response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        }
        authService.logout(userId);
        return ApiResponse.success_only(SuccessStatus.OK);
    }
}
