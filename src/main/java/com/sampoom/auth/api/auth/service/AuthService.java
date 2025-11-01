package com.sampoom.auth.api.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sampoom.auth.api.auth.dto.request.SignupRequest;
import com.sampoom.auth.api.auth.dto.response.SignupResponse;
import com.sampoom.auth.api.auth.entity.AuthUser;
import com.sampoom.auth.api.auth.event.AuthUserSignedUpEvent;
import com.sampoom.auth.api.auth.internal.dto.SignupUser;
import com.sampoom.auth.api.auth.outbox.OutboxEvent;
import com.sampoom.auth.api.auth.repository.AuthUserRepository;
import com.sampoom.auth.api.auth.outbox.OutboxRepository;
import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.exception.ConflictException;
import com.sampoom.auth.common.exception.InternalServerErrorException;
import com.sampoom.auth.common.exception.UnauthorizedException;
import com.sampoom.auth.common.response.ApiResponse;
import com.sampoom.auth.common.response.ErrorStatus;
import com.sampoom.auth.api.auth.dto.request.LoginRequest;
import com.sampoom.auth.api.auth.internal.client.UserClient;
import com.sampoom.auth.api.auth.dto.response.LoginResponse;
import com.sampoom.auth.api.auth.dto.response.RefreshResponse;
import com.sampoom.auth.common.jwt.JwtProvider;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
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
    @Value("${user.service.url:defaultValue}")
    private String userServiceUrl;
    // 인증 관련
    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshTokenService;
    private final BlacklistTokenService blacklistTokenService;
    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;
    // 통신 관련
    private final UserClient userClient;
    private final ObjectMapper objectMapper;
    private final OutboxRepository outboxRepo;
    private final ApplicationEventPublisher eventPublisher;

    public SignupResponse signup(SignupRequest req) {
        // 유저 비활성화 여부 확인
        Optional<AuthUser> user = authUserRepository.findByEmail(req.getEmail());
        if(user.isPresent()) {
                throw new ConflictException(ErrorStatus.USER_EMAIL_DUPLICATED);
        }

        // AuthUser 생성 ( 이메일, 비밀번호만 담은 User 인증 정보 )
        AuthUser authUser = authUserRepository.save(
                AuthUser.builder()
                        .email(req.getEmail())
                        .password(passwordEncoder.encode(req.getPassword()))
                        .role(Role.ROLE)
                        .build()
        );

        // Outbox 이벤트 생성 (User & Employee가 구독)
        AuthUserSignedUpEvent evt = AuthUserSignedUpEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType("UserSignedUp")
                .occurredAt(java.time.OffsetDateTime.now().toString())
                .payload(AuthUserSignedUpEvent.Payload.builder()
                        .userId(authUser.getId())
                        .email(authUser.getEmail())
                        .role(authUser.getRole())
                        .createdAt(authUser.getCreatedAt())
                        .build())
                .build();

        try {
            String payloadJson = objectMapper.writeValueAsString(evt);
            outboxRepo.save(OutboxEvent.builder()
                    .eventType(evt.getEventType())
                    .aggregateId(authUser.getId())
                    .payload(payloadJson)
                    .published(false)
                    .build());

        } catch (Exception e) {
            throw new RuntimeException("Outbox serialize failed", e);
        }

        // User 프로필 생성 ( 이메일, 비밀번호를 제외한 User 기본 정보 )
        try {
            log.info("[Feign call] user.service.url = {}", userServiceUrl);
            ApiResponse<Void> response = userClient.createProfile(SignupUser.builder()
                    .userId(authUser.getId())
                    .userName(req.getUserName())
                    .workspace(req.getWorkspace())
                    .branch(req.getBranch())
                    .position(req.getPosition())
                    .build());

            if (response == null || !response.getSuccess()) {
                log.error("[Signup] Feign call response null/failed");
                throw new InternalServerErrorException(ErrorStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (Exception e) {
            log.error("[Signup] Feign call failed", e);
            // AuthUser 롤백 보장
            throw new InternalServerErrorException(ErrorStatus.INTERNAL_SERVER_ERROR);
        }

        // 응답 DTO 반환
        return SignupResponse.builder()
                .userId(authUser.getId())
                .email(req.getEmail())
                .userName(req.getUserName())
                .build();
    }

    public LoginResponse login(LoginRequest req) {
        // user에 담자마자 이메일 존재 여부 체크
        AuthUser authUser = authUserRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new UnauthorizedException(ErrorStatus.USER_BY_EMAIL_NOT_FOUND));

        // 비밀번호 불일치
        if (!passwordEncoder.matches(req.getPassword(), authUser.getPassword())) {
            throw new UnauthorizedException(ErrorStatus.USER_PASSWORD_INVALID);
        }

        // (해당 유저만의) 기존 토큰 무효화 (단일 세션 유지)
        refreshTokenService.deleteAllByUser(authUser.getId());

        // 토큰 발급
        String jti = UUID.randomUUID().toString();
        String access = jwtProvider.createAccessToken(authUser.getId(), authUser.getRole(), jti);
        String refresh = jwtProvider.createRefreshToken(authUser.getId(), authUser.getRole(), jti);

        // 리프레시 토큰 저장
        refreshTokenService.save(authUser.getId(), jti, refresh, Instant.now().plusSeconds(refreshTokenExpiration));

        return LoginResponse.builder()
                .userId(authUser.getId())
                .role(authUser.getRole())
                .accessToken(access)
                .refreshToken(refresh)
                .expiresIn(accessTokenExpiration)
                .build();
    }


    public RefreshResponse refresh(String refreshToken) {
        // 리프레시 토큰 검증
        Claims refreshClaims;
        try {
            // 토큰 파싱 및 예외 처리
            refreshClaims = jwtProvider.parse(refreshToken); // 만료 시 ExpiredJwtException 자동 발생
        } catch (ExpiredJwtException e) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_EXPIRED);
        } catch (JwtException | IllegalArgumentException e) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
        }
        String tokenType = refreshClaims.get("type", String.class);
        if (!"refresh".equals(tokenType)) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_TYPE_INVALID);
        }

        Long userId = Long.valueOf(refreshClaims.getSubject());
        String jti = refreshClaims.getId();

        // 토큰 유효성 검증 (DB에 저장된 토큰과 비교)
        if (!refreshTokenService.validate(userId, jti, refreshToken)) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
        }

        // 동일한 jti로
        blacklistTokenService.addJti(userId, jti, refreshClaims.getExpiration().toInstant());

        // (해당 유저만의) 기존 토큰 무효화 (단일 세션 유지)
        refreshTokenService.deleteAllByUser(userId);

        // 토큰에서 바로 정보 꺼내기 (DB 조회)
        String roleStr = refreshClaims.get("role", String.class);
        Role role = Role.valueOf(roleStr);

        // 새로운 Access/Refresh 토큰 생성
        String newJti = UUID.randomUUID().toString();
        String newAccessToken = jwtProvider.createAccessToken(userId, role, newJti);
        String newRefreshToken = jwtProvider.createRefreshToken(userId, role, newJti);

        // 새 Refresh 토큰 저장
        refreshTokenService.save(userId, newJti, newRefreshToken, Instant.now().plusSeconds(refreshTokenExpiration));

        // 결과 반환
        return RefreshResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(accessTokenExpiration)
                .build();
}

    public void logout(Long userId, String accessToken) {
        Claims claims;
        // 만료된 토큰도 블랙리스트 등록
        try {
            claims = jwtProvider.parse(accessToken);
        } catch (ExpiredJwtException e) {
            claims = e.getClaims(); // 만료돼도 jti, sub, exp는 있음
        }

        if (claims == null) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_NULL_BLANK);
        }

        refreshTokenService.deleteAllByUser(userId);
        blacklistTokenService.add(accessToken, claims);

        log.info("[Logout] userId={} / jti={} / exp={}", userId, claims.getId(), claims.getExpiration());
    }


    private String stripBearer(String token) {
        if (token == null) return null;
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return token.substring(7);
        }
        return token;
    }
}
