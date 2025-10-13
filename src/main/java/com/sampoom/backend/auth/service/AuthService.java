package com.sampoom.backend.auth.service;

import com.sampoom.backend.auth.controller.dto.request.LoginRequest;
import com.sampoom.backend.auth.external.dto.VerifyLoginRequest;
import com.sampoom.backend.auth.controller.dto.response.LoginResponse;
import com.sampoom.backend.auth.controller.dto.response.RefreshResponse;
import com.sampoom.backend.auth.external.dto.UserResponse;
import com.sampoom.backend.auth.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
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

    public LoginResponse login(LoginRequest req) {
        // User 서버에 로그인 검증 요청 (이메일 + 비밀번호 전달)
        System.out.println("🔥 [DEBUG] 로그인 시도: " + req.getEmail());
        Boolean valid = userClient.verifyLogin(new VerifyLoginRequest(req.getEmail(), req.getPassword()));
        System.out.println("✅ [DEBUG] verifyLogin 결과: " + valid);
        if (!valid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        // 유저 정보 조회
        log.info("✅ verifyLogin 성공");
        UserResponse user = userClient.getUserByEmail(req.getEmail());
        log.info("✅ getUserByEmail 결과: " + user);
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "사용자를 찾을 수 없습니다.");
        }

        String access = jwtProvider.createAccessToken(user.getId(), user.getRole(), user.getName());
        String jti = UUID.randomUUID().toString();
        String refresh = jwtProvider.createRefreshToken(user.getId(), jti);

        // 리프레스 토큰 저장
        refreshService.save(user.getId(), jti, refresh, Instant.now().plusSeconds(refreshTokenExpiration));

        return LoginResponse.builder()
                .userId(user.getId())
                .username(user.getName())
                .role(user.getRole())
                .accessToken(access)
                .refreshToken(refresh)
                .expiresIn(accessTokenExpiration)
                .build();
    }

    public RefreshResponse refresh(String refreshToken) {
        Claims c = jwtProvider.parse(refreshToken);
        Long userId = Long.valueOf(c.getSubject());
        String jti = c.getId();

        if (!refreshService.validate(userId, jti, refreshToken))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰");

        refreshService.revoke(userId, jti);

        UserResponse user = userClient.getUserById(userId);
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다.");
        }

        String newJti = UUID.randomUUID().toString();
        String newAccess = jwtProvider.createAccessToken(userId, user.getRole(), user.getName());
        String newRefresh = jwtProvider.createRefreshToken(userId, newJti);
        refreshService.save(userId, newJti, newRefresh, Instant.now().plusSeconds(refreshTokenExpiration));

        return RefreshResponse.builder()
                .accessToken(newAccess)
                .expiresIn(accessTokenExpiration)
                .refreshToken(newRefresh)
                .build();
    }

    public void logout(Long userId) {
        refreshService.deleteAllByUser(userId);
    }
}
