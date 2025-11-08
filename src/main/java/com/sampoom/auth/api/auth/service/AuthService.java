package com.sampoom.auth.api.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sampoom.auth.api.auth.dto.request.RoleRequest;
import com.sampoom.auth.api.auth.dto.request.SignupRequest;
import com.sampoom.auth.api.auth.dto.response.RoleResponse;
import com.sampoom.auth.api.auth.dto.response.SignupResponse;
import com.sampoom.auth.api.auth.entity.AuthUser;
import com.sampoom.auth.api.auth.event.AuthUserSignedUpEvent;
import com.sampoom.auth.api.auth.event.AuthUserUpdatedEvent;
import com.sampoom.auth.api.auth.internal.dto.SignupUser;
import com.sampoom.auth.api.auth.outbox.OutboxEvent;
import com.sampoom.auth.api.auth.repository.AuthUserRepository;
import com.sampoom.auth.api.auth.outbox.OutboxRepository;
import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.exception.*;
import com.sampoom.auth.common.response.ErrorStatus;
import com.sampoom.auth.api.auth.dto.request.LoginRequest;
import com.sampoom.auth.api.auth.internal.client.UserClient;
import com.sampoom.auth.api.auth.dto.response.LoginResponse;
import com.sampoom.auth.api.auth.dto.response.RefreshResponse;
import com.sampoom.auth.common.jwt.JwtProvider;
import com.sampoom.auth.api.user.entity.UserProjection;
import com.sampoom.auth.api.user.repository.UserProjectionRepository;
import feign.FeignException;
import io.jsonwebtoken.*;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.ResourceAccessException;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Transactional
@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${jwt.access-ttl-seconds}")
    private Long accessTokenExpiration;
    @Value("${jwt.refresh-ttl-seconds}")
    private Long refreshTokenExpiration;
    @Value("${user.service.url:defaultValue}")
    private String userServiceUrl;
    // 인증 관련
    private final JwtProvider jwtProvider;
    private final RefreshTokenService refreshTokenService;
    private final BlacklistTokenService blacklistTokenService;
    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserProjectionRepository userProjectionRepo;
    // 통신 관련
    private final UserClient userClient;
    private final ObjectMapper objectMapper;
    private final OutboxRepository outboxRepo;

    private final EntityManager entityManager;

    public SignupResponse signup(SignupRequest req) {
        // 유저 비활성화 여부 확인
        Optional<AuthUser> user = authUserRepository.findByEmail(req.getEmail());
        if(user.isPresent()) {
                throw new ConflictException(ErrorStatus.DUPLICATED_USER_EMAIL);
        }

        // AuthUser 생성 ( 이메일, 비밀번호만 담은 User 인증 정보 )
        AuthUser authUser = authUserRepository.save(
                AuthUser.builder()
                        .email(req.getEmail())
                        .password(passwordEncoder.encode(req.getPassword()))
                        .build()
        );
        entityManager.flush();
        // Outbox 이벤트 생성 (User & Employee가 구독)
        AuthUserSignedUpEvent evt = AuthUserSignedUpEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType("AuthUserSignedUp")
                .occurredAt(java.time.OffsetDateTime.now().toString())
                .version(authUser.getVersion())
                .payload(AuthUserSignedUpEvent.Payload.builder()
                        .userId(authUser.getId())
                        .email(authUser.getEmail())
                        .role(authUser.getRole())
                        .createdAt(authUser.getCreatedAt())
                        .build())
                .build();

        // 해당 이벤트를 Outbox 저장
        try {
            String payloadJson = objectMapper.writeValueAsString(evt);
            outboxRepo.save(OutboxEvent.builder()
                    .eventType(evt.getEventType())
                    .aggregateId(authUser.getId())
                    .payload(payloadJson)
                    .published(false)
                    .build());

        } catch (Exception e) {
            throw new InternalServerErrorException(ErrorStatus.OUTBOX_SERIALIZATION_ERROR);
        }

        // User 프로필 생성 ( 이메일, 비밀번호를 제외한 User 기본 정보 )
        try {
            userClient.createProfile(SignupUser.builder()
                    .userId(authUser.getId())
                    .userName(req.getUserName())
                    .workspace(req.getWorkspace())
                    .branch(req.getBranch())
                    .position(req.getPosition())
                    .build());
        }
        // Feign 예외 처리: User 롤백 보장
        // 클라이언트 측 요청 오류
        catch (FeignException.FeignClientException e) {
            throw new BadRequestException(ErrorStatus.INVALID_REQUEST);
        }
        // 서버 측 처리 오류
        catch (FeignException.FeignServerException e) {
            throw new InternalServerErrorException(ErrorStatus.INTERNAL_SERVER_ERROR);
        }
        // 네트워크 연결 오류 (User 서비스 다운 등)
        catch (FeignException e) {
            if (e.status() == -1) {
                throw new InternalServerErrorException(ErrorStatus.FAILED_CONNECTION);
            }
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
                .orElseThrow(() -> new UnauthorizedException(ErrorStatus.NOT_FOUND_USER_BY_EMAIL));

        // 비밀번호 불일치
        if (!passwordEncoder.matches(req.getPassword(), authUser.getPassword())) {
            throw new UnauthorizedException(ErrorStatus.INVALID_USER_PASSWORD);
        }

        UserProjection userProjection = userProjectionRepo.findByUserId(authUser.getId())
                .orElse(null);
        if (userProjection == null) {
            log.warn("[AuthService] UserProjection not found for userId={}, temporary bypass", authUser.getId());
        } else {
            // 기존 workspace, status 검증
            // 워크스페이스 일치 여부 확인
            if (!Objects.equals(req.getWorkspace(), userProjection.getWorkspace())) {
                throw new BadRequestException(ErrorStatus.INVALID_WORKSPACE_TYPE);
            }

            switch (userProjection.getEmployeeStatus()) {
                case RETIRED, LEAVE -> throw new UnauthorizedException(ErrorStatus.DEACTIVATED_USER);
                case ACTIVE -> {
                } // 통과
                default -> throw new UnauthorizedException(ErrorStatus.INVALID_EMPSTATUS_TYPE);
            }
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
            throw new UnauthorizedException(ErrorStatus.EXPIRED_TOKEN);
        } catch (JwtException | IllegalArgumentException e) {
            throw new UnauthorizedException(ErrorStatus.INVALID_TOKEN);
        }
        String tokenType = refreshClaims.get("type", String.class);
        if (!"refresh".equals(tokenType)) {
            throw new UnauthorizedException(ErrorStatus.INVALID_TOKEN_TYPE);
        }

        Long userId = Long.valueOf(refreshClaims.getSubject());
        String jti = refreshClaims.getId();

        // 토큰 유효성 검증 (DB에 저장된 토큰과 비교)
        if (!refreshTokenService.validate(userId, jti, refreshToken)) {
            throw new UnauthorizedException(ErrorStatus.INVALID_TOKEN);
        }

        // 동일한 jti로
        blacklistTokenService.addJti(userId, jti, refreshClaims.getExpiration().toInstant());

        // (해당 유저만의) 기존 토큰 무효화 (단일 세션 유지)
        refreshTokenService.deleteAllByUser(userId);

        // 토큰에서 바로 정보 꺼내기 (DB 조회)
        Role role = Role.valueOf(refreshClaims.get("role", String.class));

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

    public void logout(String accessToken, String clientType) {
        // WEB
        if ("WEB".equalsIgnoreCase(clientType)) {
            if (accessToken == null) {
                return; // 이미 만료되어 쿠키 사라졌음
            }
        }
        // APP
        if (accessToken == null)
            throw new UnauthorizedException(ErrorStatus.NULL_TOKEN);
        if (accessToken.isBlank())
            throw new UnauthorizedException(ErrorStatus.BLANK_TOKEN);

        Claims claims;
        // 만료된 토큰도 블랙리스트 등록
        try {
            claims = jwtProvider.parse(accessToken);
        } catch (ExpiredJwtException e) {
            claims = e.getClaims(); // 만료돼도 claims 복원 및 로그아웃
        } catch (JwtException | IllegalArgumentException e) {
            // 완전히 위조되거나 손상된 토큰만 차단
            throw new UnauthorizedException(ErrorStatus.INVALID_TOKEN);
        }

        if (claims == null) {
            throw new UnauthorizedException(ErrorStatus.NULL_TOKEN);
        }
        Long userId = Long.valueOf(claims.getSubject());
        // 기존 리프레시/엑세스 토큰 무효화
        refreshTokenService.deleteAllByUser(userId);
        blacklistTokenService.add(accessToken, claims);
    }

    @Transactional
    public RoleResponse updateRole(Long userId, RoleRequest req) {
        if (userId == null || req==null || req.getRole() == null) {
            throw new BadRequestException(ErrorStatus.INVALID_INPUT_VALUE);
        }
        Role newRole = req.getRole();
        AuthUser authUser = authUserRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException(ErrorStatus.NOT_FOUND_USER_BY_ID));

        authUser.setRole(newRole);

        // version / updatedAt 필드가 즉시 반영되도록 flush
        authUserRepository.saveAndFlush(authUser);

        // Outbox 이벤트 생성 (User & Employee가 구독)
         AuthUserUpdatedEvent evt = AuthUserUpdatedEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType("AuthUserUpdated")
                .occurredAt(OffsetDateTime.now().toString())
                 .version(authUser.getVersion())
                .payload(AuthUserUpdatedEvent.Payload.builder()
                        .userId(authUser.getId())
                        .email(authUser.getEmail())
                        .role(authUser.getRole())
                        .updatedAt(authUser.getUpdatedAt())
                        .build())
                .build();

        // 해당 이벤트를 Outbox 저장
        try {
            String payloadJson = objectMapper.writeValueAsString(evt);
            outboxRepo.save(OutboxEvent.builder()
                    .eventType(evt.getEventType())
                    .aggregateId(authUser.getId())
                    .payload(payloadJson)
                    .published(false)
                    .build());

        } catch (Exception e) {
            throw new InternalServerErrorException(ErrorStatus.OUTBOX_SERIALIZATION_ERROR);
        }
        return RoleResponse.builder()
                .userId(authUser.getId())
                .role(authUser.getRole())
                .build();
    }
}
