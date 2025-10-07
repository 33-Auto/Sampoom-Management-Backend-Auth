package com.sampoom.backend.auth.service;

import com.sampoom.backend.auth.controller.dto.request.LoginRequest;
import com.sampoom.backend.auth.controller.dto.response.LoginResponse;
import com.sampoom.backend.auth.controller.dto.response.RefreshResponse;
import com.sampoom.backend.auth.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshService;
    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    private static final Map<String, String> USERS = Map.of(
            "sample@sample.com", "$2a$10$sumxHE51PPEmW.Wm6NIU5O9vyoCKWu4CMGRGHkYqa0ukOTkoIZ.ie"
    );

    public LoginResponse login(LoginRequest req) {
        String hash = USERS.get(req.getEmail());
        System.out.println(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode("sample1234"));

        if (hash == null || !encoder.matches(req.getPassword(), hash))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "아이디 또는 비밀번호가 올바르지 않습니다.");

        Long userId = 1L;
        String role = "ROLE_USER";
        String name = "김철수";

        String access = jwtProvider.createAccessToken(userId, role, name);
        String jti = UUID.randomUUID().toString();
        String refresh = jwtProvider.createRefreshToken(userId, jti);

        refreshService.save(userId, jti, refresh, Instant.now().plusSeconds(1209600));

        return LoginResponse.builder()
                .userId(userId)
                .username(name)
                .role(role)
                .accessToken(access)
                .refreshToken(refresh)
                .expiresIn(3600)
                .build();
    }

    public RefreshResponse refresh(String refreshToken) {
        Claims c = jwtProvider.parse(refreshToken);
        Long userId = Long.valueOf(c.getSubject());
        String jti = c.getId();

        if (!refreshService.validate(userId, jti, refreshToken))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰");

        refreshService.revoke(userId, jti);

        String newJti = UUID.randomUUID().toString();
        String newAccess = jwtProvider.createAccessToken(userId, "ROLE_USER", "김철수");
        String newRefresh = jwtProvider.createRefreshToken(userId, newJti);
        refreshService.save(userId, newJti, newRefresh, Instant.now().plusSeconds(1209600));

        return RefreshResponse.builder()
                .accessToken(newAccess)
                .expiresIn(3600)
                .refreshToken(newRefresh)
                .build();
    }

    public void logout(Long userId) {
        refreshService.deleteAllByUser(userId);
    }
}
