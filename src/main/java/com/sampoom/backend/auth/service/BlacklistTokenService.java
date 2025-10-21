package com.sampoom.backend.auth.service;

import com.sampoom.backend.auth.domain.BlacklistToken;
import com.sampoom.backend.auth.repository.BlacklistTokenRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

@Service
@RequiredArgsConstructor
@Transactional
public class BlacklistTokenService {

    private final BlacklistTokenRepository blacklistRepository;

    public void add(String accessToken, Claims claims) {
        String jti = claims.getId();
        String hash = hashToken(accessToken);
        Long userId = Long.valueOf(claims.getSubject());
        Instant expiresAt = claims.getExpiration().toInstant();

        if (!blacklistRepository.existsByTokenId(jti)) {
            blacklistRepository.save(
                    BlacklistToken.builder()
                            .userId(userId)
                            .tokenId(jti)
                            .tokenHash(hash)
                            .expiresAt(expiresAt)
                            .build()
            );
        }
    }

    public boolean isBlacklisted(String tokenId) {
        return blacklistRepository.existsByTokenId(tokenId);
    }

    public void cleanupExpiredTokens() {
        blacklistRepository.deleteAllByExpiresAtBefore(Instant.now());
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }
}
