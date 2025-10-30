package com.sampoom.auth.api.auth.dto.response;

import com.sampoom.auth.common.entity.Role;
import lombok.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponse {
    private Long userId;
    private String userName;
    private Role role;
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
}