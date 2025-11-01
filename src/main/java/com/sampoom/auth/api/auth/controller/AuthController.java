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
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import static com.sampoom.auth.api.auth.utils.CookieUtils.addAuthCookies;
import static com.sampoom.auth.api.auth.utils.CookieUtils.clearAuthCookies;

@Slf4j
@RestController
@RequiredArgsConstructor
@Tag(name="AUTH", description = "AUTH 관련 API 입니다.")
public class AuthController {

    private final AuthService authService;
    private final JwtProvider jwtProvider;
    private final JwtAuthFilter jwtAuthFilter;

    @Value("${jwt.access-ttl-seconds}")
    private long accessTtlSeconds;

    @Value("${jwt.refresh-ttl-seconds}")
    private long refreshTtlSeconds;

    @Operation(summary = "회원가입", description = "회원가입을 통해 인증 정보를 담은 유저를 생성합니다.")
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<SignupResponse>> signup(@Valid @RequestBody SignupRequest req) {
        SignupResponse resp = authService.signup(req);
        return ApiResponse.success(SuccessStatus.CREATED, resp);
    }

    @Operation(summary = "로그인", description = "로그인을 통해 토큰을 발급합니다.")
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
                    .role(resp.getRole())
                    .expiresIn(resp.getExpiresIn())
                    .build();

            return ApiResponse.success(SuccessStatus.OK, webResp);
        }

        // APP: body에 토큰 포함
        return ApiResponse.success(SuccessStatus.OK, resp);
    }


    @PostMapping("/refresh")
    @Operation(summary = "토큰 재발급", description = "리프레시 토큰을 통해 토큰을 재발급합니다.")
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

        // 토큰 유효성 검증
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
        }

        RefreshResponse resp = authService.refresh(refreshToken);

        if ("WEB".equalsIgnoreCase(clientType)) {
            addAuthCookies(response,resp.getAccessToken(),resp.getRefreshToken(), accessTtlSeconds, refreshTtlSeconds);
        }
        return ApiResponse.success(SuccessStatus.OK,resp);
    }

    @PostMapping("/logout")
    @Operation(summary = "로그아웃", description = "토큰을 초기화해 로그아웃합니다. 서버 측에 로그아웃 여부를 전달해야 할 때 명시적으로 사용합니다.")
    @SecurityRequirement(name = "bearerAuth")
    public ResponseEntity<ApiResponse<Void>> logout(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(value = "X-Client-Type", defaultValue = "APP") String clientType
    ) {
        String accessToken = jwtAuthFilter.resolveAccessToken(request, clientType);
        if (accessToken == null || accessToken.isBlank()) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_NULL_BLANK);
        }

        Claims claims;
        try {
            claims = jwtProvider.parse(accessToken);
        } catch (ExpiredJwtException e) {
            claims = e.getClaims();
            if (claims == null) {
                throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
            }
        } catch (JwtException | IllegalArgumentException e) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
        }
        Long userId = Long.valueOf(claims.getSubject());

        // WEB: 쿠키 삭제
        if ("WEB".equalsIgnoreCase(clientType)) {
            clearAuthCookies(response);
        }
        authService.logout(userId, accessToken);
        return ApiResponse.success_only(SuccessStatus.OK);
    }
}
