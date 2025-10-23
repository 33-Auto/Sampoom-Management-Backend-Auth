package com.sampoom.auth.common.config.swagger;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI() {
        SecurityScheme bearerAuth = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .name("Authorization");

        SecurityScheme cookieAuth = new SecurityScheme()
                .type(SecurityScheme.Type.APIKEY)
                .in(SecurityScheme.In.COOKIE)
                .name("ACCESS_TOKEN")
                .description("브라우저에서 자동 주입, 입력 필요 없음");

        Server localServer = new Server()
                .url("http://localhost:8081")
                .description("로컬 서버");

        Server prodServer = new Server()
                .url("https://sampoom.store/api/auth")
                .description("배포 서버");

        SecurityRequirement bearerAuthRequirement = new SecurityRequirement()
                .addList("bearerAuth");
        SecurityRequirement cookieAuthRequirement = new SecurityRequirement()
                .addList("cookieAuth");

        return new OpenAPI()
                .info(new Info()
                        .title("삼삼오토 Auth Service API")
                        .description("Auth 서비스 REST API 문서")
                        .version("1.0.0"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", bearerAuth)
                        .addSecuritySchemes("cookieAuth", cookieAuth)
                )
                .addSecurityItem(bearerAuthRequirement)
                .addSecurityItem(cookieAuthRequirement)
                .servers(List.of(localServer, prodServer));
    }
}
