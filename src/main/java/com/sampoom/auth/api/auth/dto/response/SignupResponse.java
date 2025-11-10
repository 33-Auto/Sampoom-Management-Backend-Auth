package com.sampoom.auth.api.auth.dto.response;

import com.sampoom.auth.common.entity.Workspace;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SignupResponse {
    private Long userId;
    private String userName;
    private String email;
}
