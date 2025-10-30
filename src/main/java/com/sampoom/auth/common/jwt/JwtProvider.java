package com.sampoom.auth.common.jwt;

import com.sampoom.auth.common.entity.Role;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Component
public class JwtProvider {
    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-ttl-seconds}")
    private long accessTtlSec;

    @Value("${jwt.refresh-ttl-seconds}")
    private long refreshTtlSec;

    private Key getKey() {
        // secret 문자열을 HS256용 Key 객체로 변환
        return new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName());
    }

    public String createAccessToken(Long userId, Role role, String jti) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setIssuer(issuer)
                .setSubject(String.valueOf(userId))
                .claim("type", "access")
                .claim("role", role.name())
                .setId(jti)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(accessTtlSec)))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String createRefreshToken(Long userId, Role role, String jti) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setIssuer(issuer)
                .setSubject(String.valueOf(userId))
                .claim("type", "refresh")
                .claim("role", role.name())
                .setId(jti)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(refreshTtlSec)))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parserBuilder().setSigningKey(getKey()).build()
                .parseClaimsJws(token).getBody();
    }

    // 내부 Feign용 인증 토큰
    public String issueServiceToken(String targetService) {
        Map<String, Object> claims = Map.of(
                "role", "SVC_AUTH",
                "aud", "user-service",
                "type", "service"
        );

        return Jwts.builder()
                .setIssuer("auth-service")
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
