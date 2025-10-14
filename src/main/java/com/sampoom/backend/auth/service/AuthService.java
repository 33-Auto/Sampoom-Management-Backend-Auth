package com.sampoom.backend.auth.service;

import com.sampoom.backend.auth.common.response.ApiResponse;
import com.sampoom.backend.auth.controller.dto.request.LoginRequest;
import com.sampoom.backend.auth.external.client.UserClient;
import com.sampoom.backend.auth.controller.dto.response.LoginResponse;
import com.sampoom.backend.auth.controller.dto.response.RefreshResponse;
import com.sampoom.backend.auth.external.dto.UserResponse;
import com.sampoom.backend.auth.jwt.JwtProvider;
import feign.FeignException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Transactional
@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${jwt.access-ttl-seconds}")
    private int accessTokenExpiration;
    @Value("${jwt.refresh-ttl-seconds}")
    private int refreshTokenExpiration;

    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshService;
    private final UserClient userClient;
    private final PasswordEncoder passwordEncoder;


    @Transactional
    public LoginResponse login(LoginRequest req) {
        // 바로 받아오면 예외 처리 하기 전에 에러
        ApiResponse<UserResponse> user;

        // 유저 조회 및 예외 처리
        try {
            user = userClient.getUserByEmail(req.getEmail());
        } catch (FeignException.NotFound e) {
            // 이메일 존재 X
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "존재하지 않는 이메일입니다.");
        } catch (FeignException e) {
            // User 서비스 자체 문제 (다운 등)
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "User 서비스 호출 실패");
        }

        // 비밀번호 검증
        if (!passwordEncoder.matches(req.getPassword(), user.getData().getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "비밀번호가 올바르지 않습니다.");
        }

        // 토큰 발급
        String access = jwtProvider.createAccessToken(user.getData().getId(), user.getData().getRole(), user.getData().getUserName());
        String jti = UUID.randomUUID().toString();
        String refresh = jwtProvider.createRefreshToken(user.getData().getId(), user.getData().getRole(), user.getData().getUserName(), jti);

        // 리프레시 토큰 저장
        refreshService.save(user.getData().getId(), jti, refresh, Instant.now().plusSeconds(refreshTokenExpiration));

        return LoginResponse.builder()
                .userId(user.getData().getId())
                .userName(user.getData().getUserName())
                .role(user.getData().getRole())
                .accessToken(access)
                .refreshToken(refresh)
                .expiresIn(accessTokenExpiration)
                .build();
    }


@Transactional
    public RefreshResponse refresh(String refreshToken) {
    Claims claims;
        try {
            // 토큰 파싱 및 예외 처리
            claims = jwtProvider.parse(refreshToken); // 만료 시 ExpiredJwtException 자동 발생
        } catch (ExpiredJwtException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "만료된 토큰입니다.");
        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰");
        }
        Long userId = Long.valueOf(claims.getSubject());
        String jti = claims.getId();

        // 토큰 유효성 검증 (DB에 저장된 토큰과 비교)
        if (!refreshService.validate(userId, jti, refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰");
        }

        // 토큰에서 바로 정보 꺼내기 (DB 조회)
        String role = claims.get("role", String.class);
        String name = claims.get("name", String.class);

        // (해당 유저만의) 기존 토큰 무효화 (단일 세션 유지)
        refreshService.deleteAllByUser(userId);

        // 새로운 Access/Refresh 토큰 생성
        String newJti = UUID.randomUUID().toString();
        String newAccessToken = jwtProvider.createAccessToken(userId, role, name);
        String newRefreshToken = jwtProvider.createRefreshToken(userId, role, name, newJti);

        // 새 Refresh 토큰 저장
        refreshService.save(userId, newJti, newRefreshToken, Instant.now().plusSeconds(refreshTokenExpiration));

        // 결과 반환
        return RefreshResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(accessTokenExpiration)
                .build();
}

    @Transactional
    public void logout(Long userId) {
        refreshService.deleteAllByUser(userId);
    }
}
