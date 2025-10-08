package com.sampoom.backend.auth.user.controller.dto.response;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SignupResponse {
    private Long userId;
    private String username;
    private String email;
}
