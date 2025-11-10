package com.sampoom.auth.api.auth.dto.request;

import com.sampoom.auth.common.entity.MemberRole;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleRequest {
    @NotNull
    private MemberRole role;
}
