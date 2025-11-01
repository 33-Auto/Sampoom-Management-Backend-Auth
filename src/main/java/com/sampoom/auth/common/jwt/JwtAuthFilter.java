package com.sampoom.auth.common.jwt;

import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.exception.BadRequestException;
import com.sampoom.auth.common.exception.UnauthorizedException;
import com.sampoom.auth.common.response.ErrorStatus;
import com.sampoom.auth.api.auth.service.BlacklistTokenService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final BlacklistTokenService blacklistTokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String clientType = request.getHeader("X-Client-Type");
        if (log.isDebugEnabled()) {
            log.debug("[JwtAuthFilter] Authorization 헤더 존재 여부 = {}", request.getHeader("Authorization") != null);
        }

        // X-Client-Type 헤더가 비어 있으면 APP을 기본값으로 한다.
        if (clientType == null) clientType = "APP";

        String path = request.getRequestURI();
        if (path.startsWith("/refresh") || path.startsWith("/login") || path.startsWith("/signup")  ||
            path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs") || path.equals("/swagger-ui.html")) {
            log.info("[Signup] path.startsWith 통과");
            filterChain.doFilter(request, response);
            return;
        }
        // accessToken 추출
        String accessToken = resolveAccessToken(request, clientType);

        if (accessToken != null && !accessToken.isBlank()) {
            try {
                Claims claims = jwtProvider.parse(accessToken);

                // 토큰 타입 검증
                String type = claims.get("type", String.class);
                if ("refresh".equals(type)) {
                    throw new UnauthorizedException(ErrorStatus.TOKEN_TYPE_INVALID);
                }

                // 블랙리스트 검증
                String jti = claims.getId();
                if (jti == null || jti.isBlank()) {
                    throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
                }
                if (blacklistTokenService.isBlacklisted(jti)) {
                    throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
                }

                // 토큰에서 userId, role 가져오기
                String userId = claims.getSubject();
                String roleStr = claims.get("role", String.class);
                    if (userId == null || userId.isBlank() || roleStr == null || roleStr.isBlank()) {
                        throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
                    }

                    Role role;
                    try {
                        role = Role.valueOf(roleStr);
                    } catch (IllegalArgumentException ex) {
                        throw new UnauthorizedException(ErrorStatus.TOKEN_INVALID);
                    }

                // 권한 매핑 (Enum Role → Security 권한명)
                String authority;
                switch (role) {
                    case ROLE -> authority = "ROLE_USER";
                    case ADMIN -> authority = "ROLE_ADMIN";
                    default -> authority = "ROLE_" + role.name();
                }

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

    public String resolveAccessToken(HttpServletRequest request, String clientType) {
        // 앱: Authorization 헤더만 본다
        if ("APP".equalsIgnoreCase(clientType)) {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith("Bearer ")) {
                return header.substring(7);
            }
            return null;
        }

        // 웹: 쿠키만 본다
        if ("WEB".equalsIgnoreCase(clientType) && request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(cookie.getName())) {
                    return cookie.getValue();
                } else {
                    throw new BadRequestException(ErrorStatus.TOKEN_INVALID);
                }
            }
        }
        return null;
    }
}