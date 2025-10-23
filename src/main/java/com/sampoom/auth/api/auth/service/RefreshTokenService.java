package com.sampoom.auth.api.auth.service;

import com.sampoom.auth.api.auth.entity.RefreshToken;
import com.sampoom.auth.api.auth.repository.RefreshTokenRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

@Transactional
@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    public void save(Long userId, String jti, String token, Instant expiresAt) {
        String hash = sha256(token);
        refreshTokenRepository.save(RefreshToken.builder()
                .userId(userId)
                .tokenId(jti)
                .tokenHash(hash)
                .expiresAt(expiresAt)
                .build());
    }

    public boolean validate(Long userId, String jti, String token) {
        String hash = sha256(token);
        return refreshTokenRepository.findByUserIdAndTokenId(userId, jti)
                .map(t -> t.getTokenHash().equals(hash)
                        && t.getExpiresAt().isAfter(Instant.now()))
                .orElse(false);
    }

    public void deleteAllByUser(Long userId) {
        refreshTokenRepository.deleteByUserId(userId);
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
