package com.sampoom.auth.api.auth.dto.response;

import lombok.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponse {
    private Long userId;
    private String userName;
    private String role;
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
}