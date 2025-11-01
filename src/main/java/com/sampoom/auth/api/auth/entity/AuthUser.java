package com.sampoom.auth.api.auth.entity;

import com.sampoom.auth.common.entity.BaseTimeEntity;
import com.sampoom.auth.common.entity.Role;
import jakarta.persistence.*;
import lombok.*;

import static com.sampoom.auth.common.entity.Role.ROLE;

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
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role = ROLE;

    @PrePersist
    public void prePersist() {
        if (this.role == null) this.role = ROLE;
    }
}
