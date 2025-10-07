package com.sampoom.backend.auth.service;

import com.sampoom.backend.auth.domain.RefreshToken;
import com.sampoom.backend.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository repo;

    public void save(Long userId, String jti, String token, Instant expiresAt) {
        String hash = sha256(token);
        repo.save(RefreshToken.builder()
                .userId(userId)
                .tokenId(jti)
                .tokenHash(hash)
                .expiresAt(expiresAt)
                .revoked(false)
                .build());
    }

    public boolean validate(Long userId, String jti, String token) {
        String hash = sha256(token);
        return repo.findByUserIdAndTokenIdAndRevokedFalse(userId, jti)
                .map(t -> !t.isRevoked() && t.getTokenHash().equals(hash)
                        && t.getExpiresAt().isAfter(Instant.now()))
                .orElse(false);
    }

    public void revoke(Long userId, String jti) {
        repo.findByUserIdAndTokenIdAndRevokedFalse(userId, jti)
                .ifPresent(t -> {
                    t = RefreshToken.builder()
                            .id(t.getId())
                            .userId(t.getUserId())
                            .tokenId(t.getTokenId())
                            .tokenHash(t.getTokenHash())
                            .expiresAt(t.getExpiresAt())
                            .revoked(true)
                            .build();
                    repo.save(t);
                });
    }

    public void deleteAllByUser(Long userId) {
        repo.deleteByUserId(userId);
    }

    private String sha256(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(
                    digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
