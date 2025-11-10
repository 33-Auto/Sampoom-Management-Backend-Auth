package com.sampoom.auth.api.auth.dto.response;

import com.sampoom.auth.common.entity.MemberRole;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SignupResponse {
    private Long userId;
    private String userName;
    private MemberRole role;
    private String email;
}
