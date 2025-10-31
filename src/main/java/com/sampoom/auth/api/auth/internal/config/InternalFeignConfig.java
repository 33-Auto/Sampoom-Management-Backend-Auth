package com.sampoom.auth.api.auth.internal.config;

import com.sampoom.auth.api.auth.service.AuthService;
import com.sampoom.auth.common.jwt.JwtProvider;
import feign.RequestInterceptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
public class InternalFeignConfig {

    private final JwtProvider jwtProvider;

    public InternalFeignConfig(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Bean
    public RequestInterceptor serviceTokenInterceptor() {
        return template -> {
            log.info("[Feign Request] URL = {}", template.url());
            String serviceToken = jwtProvider.issueServiceToken("user-service");
            template.header("Authorization", "Bearer " + serviceToken);
        };
    }
}
