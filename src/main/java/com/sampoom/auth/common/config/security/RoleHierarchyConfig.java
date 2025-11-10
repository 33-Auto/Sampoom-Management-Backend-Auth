package com.sampoom.auth.common.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;

@Configuration
public class RoleHierarchyConfig {
    @Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("""
                ROLE_ADMIN > ROLE_MD
                ROLE_ADMIN > ROLE_SALES
                ROLE_ADMIN > ROLE_INVENTORY
                ROLE_ADMIN > ROLE_PRODUCTION
                ROLE_ADMIN > ROLE_PURCHASE
                ROLE_ADMIN > ROLE_HR
                ROLE_ADMIN > ROLE_AGENCY
                """);
    }
}