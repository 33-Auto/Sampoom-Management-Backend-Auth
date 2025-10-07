package com.sampoom.backend.auth.controller.dto.response;

import lombok.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshResponse {
    private String accessToken;
    private String tokenType;
    private int expiresIn;
    private String refreshToken;
}
