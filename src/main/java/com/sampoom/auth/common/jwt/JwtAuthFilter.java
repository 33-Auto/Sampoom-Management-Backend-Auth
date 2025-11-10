package com.sampoom.auth.common.jwt;

import com.sampoom.auth.common.config.security.CustomAuthEntryPoint;
import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.entity.Workspace;
import com.sampoom.auth.common.exception.CustomAuthenticationException;
import com.sampoom.auth.common.response.ErrorStatus;
import com.sampoom.auth.api.auth.service.BlacklistTokenService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final BlacklistTokenService blacklistTokenService;
    private final CustomAuthEntryPoint customAuthEntryPoint;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String clientType = request.getHeader("X-Client-Type");

        // X-Client-Type 헤더가 비어 있으면 APP을 기본값으로 한다.
        if (clientType == null) clientType = "APP";

        String path = request.getRequestURI();
        if (path.startsWith("/refresh") || path.startsWith("/login") || path.startsWith("/signup") ||
                path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs") || path.equals("/swagger-ui.html")) {
            filterChain.doFilter(request, response);
            return;
        }
        // accessToken 추출
        String accessToken = jwtProvider.resolveAccessToken(request);
        log.info("[DEBUG] path={} clientType={}", path, clientType);

        try {
            if (accessToken == null) {
                throw new CustomAuthenticationException(ErrorStatus.NULL_TOKEN);
            }
            if (accessToken.isBlank()) {
                throw new CustomAuthenticationException(ErrorStatus.BLANK_TOKEN);
            }
            Claims claims = jwtProvider.parse(accessToken);

            // 토큰 타입 검증
            String type = claims.get("type", String.class);
            if ("refresh".equals(type)) {
                throw new CustomAuthenticationException(ErrorStatus.INVALID_TOKEN_TYPE);
            }

            // 블랙리스트 검증
            String jti = claims.getId();
            if (jti == null || jti.isBlank()) {
                throw new CustomAuthenticationException(ErrorStatus.INVALID_TOKEN);
            }
            if (blacklistTokenService.isBlacklisted(jti)) {
                throw new CustomAuthenticationException(ErrorStatus.INVALID_TOKEN);
            }

            // 토큰에서 userId, role 가져오기
            String userId = claims.getSubject();
            String roleStr = claims.get("role", String.class);
            String workspaceStr = claims.get("workspace", String.class);
            if (userId == null
                    || userId.isBlank()
                    || roleStr == null
                    || roleStr.isBlank()
                    || workspaceStr == null
                    || workspaceStr.isBlank()
            ) {
                throw new CustomAuthenticationException(ErrorStatus.INVALID_TOKEN);
            }

            Role role;
            try {
                role = Role.valueOf(roleStr);
            } catch (IllegalArgumentException ex) {
                throw new CustomAuthenticationException(ErrorStatus.INVALID_TOKEN);
            }

            Workspace workspace;
            try {
                workspace = Workspace.valueOf(workspaceStr);
            } catch (IllegalArgumentException ex) {
                throw new CustomAuthenticationException(ErrorStatus.INVALID_TOKEN);
            }

            // 권한 매핑 (Enum Role → Security 권한명)
            String roleAuthority = "ROLE_" + role.name();
            String workspaceAuthority = "ROLE_" + workspace.name();

            // GrantedAuthority 리스트 생성
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(roleAuthority));
            authorities.add(new SimpleGrantedAuthority(workspaceAuthority));

            // 인증 객체 생성
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userId, null, authorities
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (CustomAuthenticationException ex) {
            SecurityContextHolder.clearContext();
            customAuthEntryPoint.commence(request, response, ex);
        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
            customAuthEntryPoint.commence(request, response,
                    new CustomAuthenticationException(ErrorStatus.INVALID_TOKEN));
        }
    }
}