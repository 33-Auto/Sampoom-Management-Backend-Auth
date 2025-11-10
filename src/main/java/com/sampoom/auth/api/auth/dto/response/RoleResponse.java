package com.sampoom.auth.api.auth.dto.response;


import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.entity.Workspace;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleResponse {
    private Long userId;
    private Role role;
}
