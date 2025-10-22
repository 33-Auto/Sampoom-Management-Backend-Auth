package com.sampoom.auth.api.auth.repository;
import com.sampoom.auth.api.auth.entity.BlacklistToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface BlacklistTokenRepository extends JpaRepository<BlacklistToken, Long> {
    boolean existsByTokenId(String tokenId);
    void deleteAllByExpiresAtBefore(Instant now);
}
