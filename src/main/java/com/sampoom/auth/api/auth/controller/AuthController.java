package com.sampoom.auth.api.auth.controller;

import com.sampoom.auth.api.auth.dto.request.SignupRequest;
import com.sampoom.auth.api.auth.dto.response.SignupResponse;
import com.sampoom.auth.common.exception.UnauthorizedException;
import com.sampoom.auth.common.response.ApiResponse;
import com.sampoom.auth.common.response.ErrorStatus;
import com.sampoom.auth.common.response.SuccessStatus;
import com.sampoom.auth.api.auth.dto.request.LoginRequest;
import com.sampoom.auth.api.auth.dto.request.RefreshRequest;
import com.sampoom.auth.api.auth.dto.response.LoginResponse;
import com.sampoom.auth.api.auth.dto.response.RefreshResponse;
import com.sampoom.auth.common.jwt.JwtAuthFilter;
import com.sampoom.auth.common.jwt.JwtProvider;
import com.sampoom.auth.api.auth.service.AuthService;
import io.jsonwebtoken.Claims;
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
import org.springframework.web.bind.annotation.*;

import static com.sampoom.auth.api.auth.utils.CookieUtils.addAuthCookies;
import static com.sampoom.auth.api.auth.utils.CookieUtils.clearAuthCookies;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtProvider jwtProvider;
    private final JwtAuthFilter jwtAuthFilter;

    @Value("${jwt.access-ttl-seconds}")
    private long accessTtlSeconds;

    @Value("${jwt.refresh-ttl-seconds}")
    private long refreshTtlSeconds;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<SignupResponse>> signup(@Valid @RequestBody SignupRequest req) {
        SignupResponse resp = authService.signup(req);
        return ApiResponse.success(SuccessStatus.CREATED, resp);
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest req,
            HttpServletResponse response,
            @RequestHeader(value = "X-Client-Type", defaultValue = "APP") String clientType) {

        LoginResponse resp = authService.login(req);

        if ("WEB".equalsIgnoreCase(clientType)) {
            // 쿠키 세팅 유틸
            addAuthCookies(response,resp.getAccessToken(),resp.getRefreshToken(),accessTtlSeconds,refreshTtlSeconds);

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
    // 리프레시 토큰 추출
        String refreshToken = null;
        // WEB: 쿠키에서
        if ("WEB".equalsIgnoreCase(clientType)) {
            if (request.getCookies() != null) {
                // 두 쿠키 중에
                for (Cookie cookie : request.getCookies()) {
                    // 리프레시 토큰 쿠키인 것 추출
                    if ("REFRESH_TOKEN".equals(cookie.getName())) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }
        }
        // APP: 헤더에서
        else if ("APP".equalsIgnoreCase(clientType)) {
            if (refreshRequest != null) {
                refreshToken = refreshRequest.getRefreshToken();
            }
        }

    // 엑세스 토큰 추출
        String accessToken = null;
        // WEB: 쿠키에서
        if ("WEB".equalsIgnoreCase(clientType)) {
            if (request.getCookies() != null) {
                // 두 쿠키 중에
                for (Cookie cookie : request.getCookies()) {
                    // 엑세스 토큰 쿠키인 것 추출
                    if ("ACCESS_TOKEN".equals(cookie.getName())) {
                        accessToken = cookie.getValue();
                        break;
                    }
                }
            }
        }
        // APP: 헤더에서
        else if ("APP".equalsIgnoreCase(clientType)) {
            accessToken = jwtAuthFilter.resolveAccessToken(request, clientType);
        }

        // 토큰 유효성 검증
        if (refreshToken == null || refreshToken.isBlank() || accessToken == null || accessToken.isBlank()) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
        }

        RefreshResponse resp = authService.refresh(refreshToken, accessToken);

        if ("WEB".equalsIgnoreCase(clientType)) {
            addAuthCookies(response,resp.getAccessToken(),resp.getRefreshToken(), accessTtlSeconds, refreshTtlSeconds);
        }
        return ApiResponse.success(SuccessStatus.OK,resp);
    }


    @PostMapping("/logout")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse<Void>> logout(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(value = "X-Client-Type", defaultValue = "APP") String clientType
    ) {
        String accessToken = jwtAuthFilter.resolveAccessToken(request, clientType);
        Claims claims = jwtProvider.parse(accessToken);

        Long userId = Long.valueOf(claims.getSubject());

        // WEB: 쿠키 삭제
        if ("WEB".equalsIgnoreCase(clientType)) {
            clearAuthCookies(response);
        }


        authService.logout(userId, accessToken);
        return ApiResponse.success_only(SuccessStatus.OK);
    }
}
