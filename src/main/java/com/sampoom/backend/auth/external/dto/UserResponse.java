package com.sampoom.backend.auth.external.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * User 서비스에서 내려주는 사용자 정보 DTO
 * - auth 서비스에서는 이 객체로 로그인 검증 및 토큰 생성에 필요한 정보를 사용한다.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    private Long id;          // 사용자 ID
    private String email;     // 이메일 (아이디)
    private String userName;      // 사용자 이름
    private String role;      // 권한 (e.g. ROLE_USER, ROLE_ADMIN)
    private String password;  // 비밀번호
}

