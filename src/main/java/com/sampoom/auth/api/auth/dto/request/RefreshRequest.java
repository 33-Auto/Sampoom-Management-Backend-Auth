package com.sampoom.auth.api.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshRequest {
    @NotBlank(message = "리프레시 토큰은 필수입니다")
    private String refreshToken;
}
