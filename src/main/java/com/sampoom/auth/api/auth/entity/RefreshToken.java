package com.sampoom.auth.api.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "refresh_token")
@Getter @NoArgsConstructor @AllArgsConstructor @Builder
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long userId;        // 사용자 ID

    @Column(nullable = false, unique = true)
    private String tokenId;     // JWT jti

    @Column(nullable = false, unique = true)
    private String tokenHash;   // 토큰 SHA-256 해시

    @Column(nullable = false)
    private Instant expiresAt;  // 토큰 만료 시간
}
