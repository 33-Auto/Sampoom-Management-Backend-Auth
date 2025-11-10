package com.sampoom.auth.api.auth.entity;

import com.sampoom.auth.common.entity.BaseTimeEntity;
import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.entity.SoftDeleteEntity;
import jakarta.persistence.*;
import lombok.*;


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

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Version
    @Column(nullable = false)
    private Long version; // 낙관적 락 & 이벤트 버전 관리

    @PrePersist
    public void prePersist() {
        if (version == null) version = 0L;
    }

    @PreUpdate
    public void preUpdate() {
        if (version == null) version = 0L;
    }

    public void setRole(Role newRole) {
        this.role = newRole;
    }

}
