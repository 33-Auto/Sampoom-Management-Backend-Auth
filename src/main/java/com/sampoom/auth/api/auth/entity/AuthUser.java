package com.sampoom.auth.api.auth.entity;

import com.sampoom.auth.common.entity.BaseTimeEntity;
import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.entity.SoftDeleteEntity;
import jakarta.persistence.*;
import lombok.*;

import static com.sampoom.auth.common.entity.Role.USER;

@Entity
@Table(name = "auth_user")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthUser extends SoftDeleteEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(nullable = false)
    private String password;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role = USER;

    @Version
    private Long version; // 낙관적 락 & 이벤트 버전 관리

    @PrePersist
    public void prePersist() {
        if (this.role == null) this.role = USER;
    }

    public void setRole(Role newRole) {
        this.role = newRole;
    }
}
