package com.sampoom.backend.auth.jwt;

import com.sampoom.backend.auth.common.exception.UnauthorizedException;
import com.sampoom.backend.auth.common.response.ErrorStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
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
        String accessToken = resolveAccessToken(request);

        if (accessToken != null) {
            if (accessToken.startsWith("Bearer ")) {
                accessToken = accessToken.substring(7);
            }
            try {
                Claims claims = jwtProvider.parse(accessToken);
                // 토큰 타입 검증
                String type = claims.get("type", String.class);
                if ("refresh".equals(type)) {
                    throw new UnauthorizedException(ErrorStatus.TOKEN_TYPE_INVALID);
                }
                // 토큰에서 userId, role 가져오기
                String userId = claims.getSubject();
                String role = claims.get("role", String.class);
                if (userId == null|| userId.isBlank() || role == null || role.isBlank()) {
                        SecurityContextHolder.clearContext();
                        filterChain.doFilter(request, response);
                        return;
                }
                // Spring Security는 ROLE_ 접두사를 기대함
                // 접두사가 없으면 붙여주고, 있으면 그대로 둔다.
                String authority = role.startsWith("ROLE_") ? role : "ROLE_" + role;
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userId, null, List.of(() -> authority)
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                // 토큰 검증 실패 시 SecurityContext 비움
                SecurityContextHolder.clearContext();
                throw e;
            }
        }

        filterChain.doFilter(request, response);
    }

    // 쿠키에서 엑세스 토큰 인증
    private String resolveAccessToken(HttpServletRequest request) {
        // 쿠키에서 ACCESS_TOKEN 검색
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        // Swagger나 테스트용으로 헤더도 허용
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }
}
