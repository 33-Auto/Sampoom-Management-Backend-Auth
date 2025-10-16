package com.sampoom.backend.auth.external.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    private Long userId;          // 사용자 ID
    private String email;     // 이메일 (아이디)
    private String userName;  // 사용자 이름
    private String role;      // 권한 (e.g. ROLE_USER, ROLE_ADMIN)
}

