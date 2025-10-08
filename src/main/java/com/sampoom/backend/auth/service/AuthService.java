package com.sampoom.backend.auth.service;

import com.sampoom.backend.auth.controller.dto.request.LoginRequest;
import com.sampoom.backend.auth.controller.dto.response.LoginResponse;
import com.sampoom.backend.auth.controller.dto.response.RefreshResponse;
import com.sampoom.backend.auth.jwt.JwtProvider;
import com.sampoom.backend.auth.user.domain.User;
import com.sampoom.backend.auth.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

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
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

//    private static final Map<String, String> USERS = Map.of(
//            "sample@sample.com", "$2a$10$sumxHE51PPEmW.Wm6NIU5O9vyoCKWu4CMGRGHkYqa0ukOTkoIZ.ie"
//    );
    private final UserRepository userRepository;

    public LoginResponse login(LoginRequest req) {
        User user = userRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 올바르지 않습니다."));

        if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        String access = jwtProvider.createAccessToken(user.getId(), user.getRole(), user.getName());
        String jti = UUID.randomUUID().toString();
        String refresh = jwtProvider.createRefreshToken(user.getId(), jti);

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

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."));

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
