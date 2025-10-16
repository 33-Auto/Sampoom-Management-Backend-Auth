package com.sampoom.backend.auth.external.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class VerifyLoginRequest {
    private String email;
    private String password;
}
