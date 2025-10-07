package com.sampoom.backend.auth.domain;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "refresh_token")
@Getter @NoArgsConstructor @AllArgsConstructor @Builder
public class RefreshToken {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;
    private String tokenId;     // JWT jti
    private String tokenHash;   // SHA256 해시
    private Instant expiresAt;
    private boolean revoked;
}
