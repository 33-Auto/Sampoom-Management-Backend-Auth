    package com.sampoom.auth.api.auth.controller;

    import com.sampoom.auth.api.auth.dto.request.RoleRequest;
    import com.sampoom.auth.api.auth.dto.request.SignupRequest;
    import com.sampoom.auth.api.auth.dto.response.RoleResponse;
    import com.sampoom.auth.api.auth.dto.response.SignupResponse;
    import com.sampoom.auth.common.entity.Workspace;
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
    import org.springframework.security.access.prepost.PreAuthorize;
    import org.springframework.security.core.Authentication;
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
            // WEB: 쿠키에서 추출
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
            // APP: 헤더에서 추출
            else if ("APP".equalsIgnoreCase(clientType)) {
                if (refreshRequest != null) {
                    refreshToken = refreshRequest.getRefreshToken();
                }
            }

            RefreshResponse resp = authService.refresh(refreshToken);

            if ("WEB".equalsIgnoreCase(clientType)) {
                // 쿠키 세팅 유틸
                addAuthCookies(response,resp.getAccessToken(),resp.getRefreshToken(), accessTtlSeconds, refreshTtlSeconds);
                // WEB: body에 토큰 제외
                RefreshResponse webResp = RefreshResponse.builder()
                        .expiresIn(resp.getExpiresIn())
                        .build();
                return ApiResponse.success(SuccessStatus.OK, webResp);
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
            String accessToken = jwtProvider.resolveAccessToken(request);
            // 서비스에서 모든 예외 및 분기 처리 (WEB/APP 구분 포함)
            authService.logout(accessToken, clientType);

            // WEB의 경우, 쿠키 삭제
            if ("WEB".equalsIgnoreCase(clientType)) {
                clearAuthCookies(response);
            }

            return ApiResponse.success_only(SuccessStatus.OK);
        }

        @PatchMapping("/role/{userId}")
        @PreAuthorize("hasAuthority('ROLE_ADMIN')")
        @Operation(summary = "권한 변경", description = "특정 유저의 접근 권한을 변경합니다. 관리자 권한만 변경이 가능합니다.")
        public ResponseEntity<ApiResponse<RoleResponse>> changeRole(
                Authentication authentication,
                @PathVariable Long userId,
                @RequestBody RoleRequest roleRequest
        ) {
            Long adminId = Long.valueOf(authentication.getName());
            log.info("관리자ID: {} 관리자가 -> 직원ID: {} 직원의 권한 정보를 수정했습니다. ", adminId, userId);
            RoleResponse resp = authService.updateRole(userId, roleRequest);
            return ApiResponse.success(SuccessStatus.OK, resp);
        }
    }
