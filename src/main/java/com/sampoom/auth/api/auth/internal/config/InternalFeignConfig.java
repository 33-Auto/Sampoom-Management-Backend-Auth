package com.sampoom.auth.api.auth.internal.config;

import com.sampoom.auth.api.auth.service.AuthService;
import com.sampoom.auth.common.jwt.JwtProvider;
import feign.RequestInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class InternalFeignConfig {

    private final JwtProvider jwtProvider;

    public InternalFeignConfig(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Bean
    public RequestInterceptor serviceTokenInterceptor() {
        return template -> {
            String serviceToken = jwtProvider.issueServiceToken("user-service");
            template.header("Authorization", "Bearer " + serviceToken);
        };
    }
}
