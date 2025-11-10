package com.sampoom.auth.common.jwt;

import com.sampoom.auth.common.entity.Role;
import com.sampoom.auth.common.exception.BadRequestException;
import com.sampoom.auth.common.exception.CustomAuthenticationException;
import com.sampoom.auth.common.exception.UnauthorizedException;
import com.sampoom.auth.common.response.ErrorStatus;
import io.jsonwebtoken.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Component
public class JwtProvider {
    @Value("${jwt.issuer}")
    private String issuer;

//    @Value("${jwt.secret}")
//    private String secret;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    @Value("${jwt.access-ttl-seconds}")
    private long accessTtlSec;

    @Value("${jwt.refresh-ttl-seconds}")
    private long refreshTtlSec;

    public JwtProvider(
            @Value("${jwt.private-key-base64}") String privateKeyBase64,
            @Value("${jwt.public-key-base64}") String publicKeyBase64
    ) throws Exception {
        this.privateKey = loadPrivateKey(privateKeyBase64);
        this.publicKey = loadPublicKey(publicKeyBase64);
    }

    private PrivateKey loadPrivateKey(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    private PublicKey loadPublicKey(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
    }


//    private Key getKey() {
//        // secret 문자열을 HS256용 Key 객체로 변환
//        return new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName());
//    }

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
                .signWith(privateKey, SignatureAlgorithm.RS256)
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
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public String resolveAccessToken(HttpServletRequest request) {
        // 쿠키에서 ACCESS_TOKEN 찾기
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        // Bearer 방식일 때
        String header = request.getHeader("Authorization");
        if (header == null) return null;
        if (!header.startsWith("Bearer "))
            throw new UnauthorizedException(ErrorStatus.INVALID_TOKEN);
        return header.substring(7); // "Bearer " 제거
    }

    public Claims parse(String token) {
        if (token == null) {
            throw new BadRequestException(ErrorStatus.NULL_TOKEN);
        }
        if (token.isBlank()){
            throw new BadRequestException(ErrorStatus.BLANK_TOKEN);
        }
        try{
            return Jwts.parserBuilder().setSigningKey(publicKey).build()
                    .parseClaimsJws(token).getBody();
        }
        catch (ExpiredJwtException e) {
            throw new CustomAuthenticationException(ErrorStatus.EXPIRED_TOKEN);
        }
        catch (Exception e) {
            // 잘못된 형식 or 위조된 토큰
            throw new CustomAuthenticationException(ErrorStatus.INVALID_TOKEN);
        }
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
                .setSubject("auth-service")
                .setClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }
}
