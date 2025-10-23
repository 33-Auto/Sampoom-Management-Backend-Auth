package com.sampoom.auth.api.auth.service;

import com.sampoom.auth.common.exception.InternalServerErrorException;
import com.sampoom.auth.common.exception.NotFoundException;
import com.sampoom.auth.common.exception.UnauthorizedException;
import com.sampoom.auth.common.response.ApiResponse;
import com.sampoom.auth.common.response.ErrorStatus;
import com.sampoom.auth.api.auth.dto.request.LoginRequest;
import com.sampoom.auth.api.auth.external.client.UserClient;
import com.sampoom.auth.api.auth.dto.response.LoginResponse;
import com.sampoom.auth.api.auth.dto.response.RefreshResponse;
import com.sampoom.auth.api.auth.external.dto.UserResponse;
import com.sampoom.auth.api.auth.external.dto.VerifyLoginRequest;
import com.sampoom.auth.common.jwt.JwtProvider;
import feign.FeignException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
    private final RefreshTokenService refreshTokenService;
    private final BlacklistTokenService blacklistTokenService;
    private final UserClient userClient;


    @Transactional
    public LoginResponse login(LoginRequest req) {
        // 바로 받아오면 예외 처리 하기 전에 에러
        ApiResponse<UserResponse> user;

        // 유저 조회 및 예외 처리
        try {
            user = userClient.verifyLogin(new VerifyLoginRequest(req.getEmail(),req.getPassword()));
        } catch (FeignException.NotFound e) {
            // 이메일 존재 X
            throw new NotFoundException(ErrorStatus.USER_BY_EMAIL_NOT_FOUND);
        } catch (FeignException.Unauthorized e){
            // 비밀번호 불일치
            throw new UnauthorizedException(ErrorStatus.USER_PASSWORD_INVALID);
        } catch (FeignException.InternalServerError e) {
            // User 서비스 자체 문제 (다운 등)
            throw new InternalServerErrorException(ErrorStatus.INTERNAL_SERVER_ERROR);
        }
        UserResponse userResponse = user.getData();

        // (해당 유저만의) 기존 토큰 무효화 (단일 세션 유지)
        refreshTokenService.deleteAllByUser(userResponse.getUserId());

        // 토큰 발급
        String jti = UUID.randomUUID().toString();
        String access = jwtProvider.createAccessToken(userResponse.getUserId(), userResponse.getRole(), userResponse.getUserName(),jti);
        String refresh = jwtProvider.createRefreshToken(userResponse.getUserId(), userResponse.getRole(), userResponse.getUserName(), jti);

        // 리프레시 토큰 저장
        refreshTokenService.save(userResponse.getUserId(), jti, refresh, Instant.now().plusSeconds(refreshTokenExpiration));

        return LoginResponse.builder()
                .userId(userResponse.getUserId())
                .userName(userResponse.getUserName())
                .role(userResponse.getRole())
                .accessToken(access)
                .refreshToken(refresh)
                .expiresIn(accessTokenExpiration)
                .build();
    }


    @Transactional
    public RefreshResponse refresh(String refreshToken, String accessToken) {
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

        Long userId = Long.valueOf(refreshClaims.getSubject());
        String jti = refreshClaims.getId();

        // 토큰 유효성 검증 (DB에 저장된 토큰과 비교)
        if (!refreshTokenService.validate(userId, jti, refreshToken)) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
        }

        // 엑세스 토큰 처리
        Claims accessClaims;
        String normalizedAccessToken=stripBearer(accessToken);
        if (normalizedAccessToken != null && !normalizedAccessToken.isBlank()) {
        }
        // 기존 AccessToken 블랙리스트 등록 (만료돼도 등록 가능)
        try {
            accessClaims = jwtProvider.parse(normalizedAccessToken);
            blacklistTokenService.add(normalizedAccessToken, accessClaims);
        } catch (ExpiredJwtException e) {
            accessClaims = e.getClaims();
            if (accessClaims != null) {
                blacklistTokenService.add(normalizedAccessToken, accessClaims);
            }
        } catch (JwtException | IllegalArgumentException e) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
        }

        // 교차 검증: refresh와 access가 동일 사용자/세션(jti)인지 확인
        if (!userId.equals(Long.valueOf(accessClaims.getSubject())) || !jti.equals(accessClaims.getId())) {
            throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
        }

        // (해당 유저만의) 기존 토큰 무효화 (단일 세션 유지)
        refreshTokenService.deleteAllByUser(userId);

        // 토큰에서 바로 정보 꺼내기 (DB 조회)
        String role = refreshClaims.get("role", String.class);
        String name = refreshClaims.get("name", String.class);

        // 새로운 Access/Refresh 토큰 생성
        String newJti = UUID.randomUUID().toString();
        String newAccessToken = jwtProvider.createAccessToken(userId, role, name, newJti);
        String newRefreshToken = jwtProvider.createRefreshToken(userId, role, name, newJti);

        // 새 Refresh 토큰 저장
        refreshTokenService.save(userId, newJti, newRefreshToken, Instant.now().plusSeconds(refreshTokenExpiration));

        // 결과 반환
        return RefreshResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(accessTokenExpiration)
                .build();
}

    @Transactional
    public void logout(Long userId, String accessToken) {
        refreshTokenService.deleteAllByUser(userId);

        Claims claims = jwtProvider.parse(accessToken);
        blacklistTokenService.add(accessToken, claims);
    }


    private String stripBearer(String token) {
        if (token == null) return null;
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return token.substring(7);
        }
        return token;
    }
}
