package com.sampoom.backend.auth.jwt;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                String token = authHeader.substring(7);
                Claims claims = jwtProvider.parse(token);

                String role = claims.get("role", String.class);

                if (role == null || role.isBlank()) {
                        SecurityContextHolder.clearContext();
                        filterChain.doFilter(request, response);
                        return;
                }
                // Spring Security는 ROLE_ 접두사를 기대함
                // 접수사가 없으면 붙여주고, 있으면 그대로 둔다.
                String authority = role.startsWith("ROLE_") ? role : "ROLE_" + role;
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        claims.getSubject(), null, List.of(() -> authority)
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                // 토큰 검증 실패 시 SecurityContext 비움
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
        System.out.println("📡 들어온 HTTP 메서드: " + request.getMethod());
        System.out.println("📡 들어온 URI: " + request.getRequestURI());
        System.out.println("📦 Authorization 헤더: " + request.getHeader("Authorization"));
    }
}
