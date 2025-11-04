package com.sampoom.auth.api.auth.service;

import com.sampoom.auth.api.auth.entity.BlacklistToken;
import com.sampoom.auth.api.auth.repository.BlacklistTokenRepository;
import com.sampoom.auth.common.exception.BadRequestException;
import com.sampoom.auth.common.exception.UnauthorizedException;
import com.sampoom.auth.common.response.ErrorStatus;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class BlacklistTokenService {

    private final BlacklistTokenRepository blacklistRepository;

    public void addJti(Long userId, String jti, Instant expiresAt) {
        if (jti == null || jti.isBlank()) {
            throw new UnauthorizedException(ErrorStatus.INVALID_TOKEN);
        }
        if (userId == null || expiresAt == null) {
            throw new BadRequestException(ErrorStatus.NULL_EXPIRATION);
        }

        if (!blacklistRepository.existsByTokenId(jti)) {
            blacklistRepository.save(
                    BlacklistToken.builder()
                            .userId(userId)
                            .tokenId(jti)
                            .tokenHash(hashString(jti)) // JTI해싱해서 저장
                            .expiresAt(expiresAt)
                            .build()
            );
        }
    }
    public void add(String accessToken, Claims claims) {
        String jti = claims.getId();
        if (jti == null || jti.isBlank()) {
            throw new UnauthorizedException(ErrorStatus.INVALID_TOKEN);
        }
        String hash = hashString(accessToken);
        Long userId;

        try {
            userId = Long.valueOf(claims.getSubject());
        } catch (NumberFormatException e) {
            throw new BadRequestException(ErrorStatus.INVALID_TOKEN);
        }
        Date exp = claims.getExpiration();
        if (exp == null) {
            throw new BadRequestException(ErrorStatus.NULL_EXPIRATION); // 토큰 만료시간 누락 시 안전하게 중단
        }
        Instant expiresAt = claims.getExpiration().toInstant();

        if (!blacklistRepository.existsByTokenId(jti)) {
            blacklistRepository.save(
                    BlacklistToken.builder()
                            .userId(userId)
                            .tokenId(jti)
                            .tokenHash(hash)    // 해싱해서 저장
                            .expiresAt(expiresAt)
                            .build()
            );
        }
    }

    public boolean isBlacklisted(String tokenId) {
        // 우회될 가능성 고려, Null/공백일 때
        if (tokenId == null || tokenId.isBlank()) return true;
        return blacklistRepository.existsByTokenId(tokenId);
    }

    // 만료된 블랙리스트 자동 정리 (스케줄러)
    @Scheduled(cron = "0 0 * * * *") // 매시간 실행
    @Transactional
    public void cleanupExpiredTokens() {
        int deletedTokens = blacklistRepository.deleteAllByExpiresAtBefore(Instant.now());
        if (deletedTokens > 0) {
            log.info("블랙리스트 : {}", deletedTokens);
        }
    }

    private String hashString(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }
}
