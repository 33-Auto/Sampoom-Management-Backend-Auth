package com.sampoom.backend.auth.external.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class VerifyLoginRequest {
    @NotBlank
    @Email
    private String email;
    @NotBlank
    private String password;
}
