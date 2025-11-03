package com.sampoom.auth.api.auth.internal.dto;

import com.sampoom.auth.common.entity.Workspace;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@NotNull
@NotBlank
public class LoginUserRequest {
    private Long userId;       // Auth에서 생성한 userId
    private Workspace workspace;  // 근무지(대리점, 창고, 공장 등)
}