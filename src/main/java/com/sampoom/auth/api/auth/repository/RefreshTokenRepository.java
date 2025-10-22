package com.sampoom.auth.api.auth.repository;

import com.sampoom.auth.api.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByUserIdAndTokenId(Long userId, String tokenId);
    void deleteByUserId(Long userId);
}
