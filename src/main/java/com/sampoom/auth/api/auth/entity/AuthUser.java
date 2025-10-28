package com.sampoom.auth.api.auth.entity;

import com.sampoom.auth.common.entity.BaseTimeEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "auth_user")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthUser extends BaseTimeEntity {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(nullable = false)
    private String password;

    @Builder.Default
    @Column(nullable = false)
    private String role;

    @Builder.Default
    @Column(nullable = false)
    private boolean isDeleted;

    private LocalDateTime deletedAt;

    @PrePersist
    public void prePersist() {
        if (this.role == null) this.role = "ROLE_USER";
    }

    // 유저 비활성화
    public void softDelete() {
        this.isDeleted = true;
        this.deletedAt = LocalDateTime.now();
    }

    // 유저 재활성화: 최근 비활성화 이력 보존
    public void restore() {
        this.isDeleted = false;
    }
}
