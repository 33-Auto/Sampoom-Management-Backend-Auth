package com.sampoom.auth.api.auth.repository;
import com.sampoom.auth.api.auth.entity.BlacklistToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;

public interface BlacklistTokenRepository extends JpaRepository<BlacklistToken, Long> {
    boolean existsByTokenId(String tokenId);
    @Modifying
    @Query("DELETE FROM BlacklistToken b WHERE b.expiresAt < :now")
    int deleteAllByExpiresAtBefore(Instant now);
}
