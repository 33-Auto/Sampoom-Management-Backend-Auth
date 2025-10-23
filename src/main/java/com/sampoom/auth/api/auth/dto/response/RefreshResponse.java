package com.sampoom.auth.api.auth.dto.response;

import lombok.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshResponse {
    private String accessToken;
    private int expiresIn;
    private String refreshToken;
}
