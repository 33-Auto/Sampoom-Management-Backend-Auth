package com.sampoom.auth.common.config.security;

import com.sampoom.auth.common.jwt.JwtAuthFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter,CustomAuthEntryPoint customAuthEntryPoint) throws Exception {
        http
                .logout(logout -> logout.disable())
                // CodeQL [java/spring-disabled-csrf-protection]: suppress - Stateless JWT API라 CSRF 불필요
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/signup",
                                "/login",
                                "/refresh",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/webjars/**").permitAll()
                        .anyRequest().authenticated()
                )
                // 기본 폼 로그인 비활성화
                .formLogin(login -> login.disable())
                .httpBasic(basic -> basic.disable())
                // 세션 미사용 명시
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // CORS 비활성화(배포 시)
//                .cors(cors -> cors.configurationSource(request -> {
//                    var corsConfig = new CorsConfiguration();
//                    corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
//                    corsConfig.setAllowedOrigins(List.of("https://sampoom.store"
//                            ,"https://samsam.autos"
//                            ,"https://sampoom-management-frontend.vercel.app"
//                            ,"http://localhost:8081"
//                            ,"http://localhost:3000"
//                    ));
//                    corsConfig.setAllowCredentials(true);
//                    corsConfig.setExposedHeaders(List.of("Authorization"));
//                    corsConfig.setAllowedHeaders(List.of("Content-Type", "Authorization", "X-Client-Type"));
//                    return corsConfig;
//                }))
                .addFilterAfter(jwtAuthFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex
                        // 인증 실패 시 INVALID_TOKEN
                        .authenticationEntryPoint(customAuthEntryPoint)
                );
        return http.build();
    }

    // 비밀번호 암호화
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Spring Security 자동 보안 설정 해제
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            throw new UsernameNotFoundException("UserDetailsService는 사용하지 않습니다.");
        };
    }
}
