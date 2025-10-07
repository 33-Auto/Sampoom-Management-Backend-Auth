package com.sampoom.backend.auth.controller.dto.request;

import lombok.*;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshRequest {
    private String refreshToken;
}
