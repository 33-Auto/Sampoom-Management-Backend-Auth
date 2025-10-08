package com.sampoom.backend.auth.user.controller.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class SignupRequest {
    private String email;
    private String password;
    private String workspace;
    private String location;
    private String branch;
    private String name;
    private String position;
}
