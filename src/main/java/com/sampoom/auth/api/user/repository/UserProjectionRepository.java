package com.sampoom.auth.api.user.repository;

import com.sampoom.auth.api.user.entity.UserProjection;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserProjectionRepository extends JpaRepository<UserProjection, Long> {
    Optional<UserProjection> findByUserId(Long userId);
}
