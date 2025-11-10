package com.sampoom.auth.api.auth.dto.response;

import com.sampoom.auth.common.entity.Role;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SignupResponse {
    private Long userId;
    private String userName;
    private Role role;
    private String email;
}
