package com.sampoom.backend.auth.repository;
import com.sampoom.backend.auth.domain.BlacklistToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface BlacklistTokenRepository extends JpaRepository<BlacklistToken, Long> {
    boolean existsByTokenId(String tokenId);
    void deleteAllByExpiresAtBefore(Instant now);
}
