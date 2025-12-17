package org.nas.gateway.filters.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.nas.gateway.common.model.LoginStatus;
import org.nas.gateway.entity.user.UserDetail;
import org.nas.gateway.properties.JwtProperties;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import javax.crypto.SecretKey;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey secretKey;

    private static final long ACCESS_TOKEN_VALIDITY = 30 * 60 * 1000L;     // 30분
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 7 * 24 * 60 * 60 * 1000L; // 7일 (ms)

    private static final String ACCESS_SUBJECT = "accessToken";
    private static final String REFRESH_SUBJECT = "refreshToken";

    public JwtTokenProvider(JwtProperties jwtProperties) {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecretKey());
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(UserDetail user) {
        return createToken(user, ACCESS_TOKEN_VALIDITY, ACCESS_SUBJECT);
    }

    public String generateRefreshToken(UserDetail user) {
        return createToken(user, REFRESH_TOKEN_EXPIRE_TIME, REFRESH_SUBJECT);
    }

    private String createToken(UserDetail user, long duration, String subject) {
        return Jwts.builder()
                .subject(subject)
                .claim("userCode", user.getUserCode())
                .claim("userName", user.getUserName())
                .claim("role", user.getRoleGroup())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + duration))
                .signWith(secretKey)
                .compact();
    }

    public Mono<LoginStatus> getClaims(String token) {
        return Mono.fromCallable(() -> {

            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token) // ✔ 서명 + exp 검증 여기서 끝
                    .getPayload();

            return LoginStatus.getSuccess(
                    claims.get("userCode", String.class),
                    claims.get("userName", String.class),
                    claims.get("role", String.class)
            );

        }).subscribeOn(Schedulers.boundedElastic()); // WebFlux 보호용
    }

    /* ========================================
        CustomJwtAuthenticationFilter 에서 사용
    ======================================== */

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);
            return true;

        /**
         * 토큰의 exp(만료 시간)가 현재 시간보다 과거인 경우
         * → 정상적으로 발급되었지만 유효기간이 끝난 토큰
         * → 보통 401 반환 + refresh 토큰 처리 대상
         */
        } catch (ExpiredJwtException e) {
            log.info("JWT expired");

        /**
         * 토큰 서명이 서버의 secretKey로 검증되지 않는 경우
         * → 토큰 위·변조 가능성
         * → 즉시 인증 실패 처리 (보안상 중요)
         */
        } catch (SignatureException e) {
            log.warn("JWT signature invalid");

        /**
         * JWT 형식 자체가 깨져있는 경우
         * 예) 점(.) 개수 오류, Base64 디코딩 실패 등
         * → 클라이언트가 잘못된 토큰을 보낸 상황
         */
        } catch (MalformedJwtException e) {
            log.warn("JWT malformed");

        /**
         * 서버가 지원하지 않는 JWT 형식인 경우
         * 예) JWE, 압축 JWT 등
         * → 일반적인 서비스에서는 거의 발생하지 않음
         */
        } catch (UnsupportedJwtException e) {
            log.warn("JWT unsupported");

        /**
         * 위에 명시한 JWT 예외들의 부모 클래스
         * → 기타 JWT 관련 오류 전반 처리
         */
        } catch (JwtException e) {
            log.warn("JWT invalid: {}", e.getMessage());

        /**
         * JWT 라이브러리 외의 예상치 못한 오류
         * 예) secretKey 설정 오류, NullPointerException 등
         * → Filter 계층 보호용 방어 코드
         */
        } catch (Exception e) {
            log.error("Unexpected token error", e);
        }

        return false;
    }

   /* =========================
        보조 메서드 (선택)
   ========================= */

    public String getAccessSubject(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public String getClaimsUserCode(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.get("userCode", String.class);
    }
}
