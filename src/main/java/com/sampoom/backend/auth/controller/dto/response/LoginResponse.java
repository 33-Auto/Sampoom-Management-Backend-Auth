package com.sampoom.backend.auth.controller.dto.response;

import lombok.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponse {
    private Long userId;
    private String username;
    private String role;
    private String accessToken;
    private String refreshToken;
    private int expiresIn;
}
