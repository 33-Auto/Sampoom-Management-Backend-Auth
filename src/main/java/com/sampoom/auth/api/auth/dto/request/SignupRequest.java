package com.sampoom.auth.api.auth.dto.request;

import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.entity.Workspace;
import com.sampoom.auth.common.entity.Position;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class SignupRequest {
    // AuthUser
    @NotBlank
    @Email
    private String email;
    @NotBlank
    @Size(min = 8, max = 64)
    private String password;

    @NotBlank
    private Workspace workspace;

    // User(Profile)
    @NotBlank
    private String userName;

    // Employee
    private String branch;
    private Position position;
}
