package org.hooni.gateway.filters.jwt;

import io.jsonwebtoken.Jwts;
import org.hooni.gateway.common.model.LoginStatus;
import org.hooni.gateway.properties.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenProviderTest {

    private JwtProperties properties;
    private JwtTokenProvider provider;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();

        properties = new JwtProperties();
        properties.setJwkSetUri(null);
        properties.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        provider = new JwtTokenProvider(properties);
    }

    @Test
    void acceptsAccessTokenWithRequiredClaims() {
        LoginStatus status = provider.parseAccessToken(token(
                properties.getIssuer(), properties.getAudience(), "AUTH_USER", "ROLE_USER", true,
                Jwts.SIG.RS256
        )).block();

        assertThat(status.getUserCode()).isEqualTo("AUTH_USER");
        assertThat(status.getRole()).isEqualTo("ROLE_USER");
    }

    @Test
    void rejectsUnexpectedAudience() {
        assertThatThrownBy(() -> provider.parseAccessToken(token(
                properties.getIssuer(), "other-service", "AUTH_USER", "ROLE_USER", true,
                Jwts.SIG.RS256
        )).block()).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTokenWithoutRequiredUserCode() {
        assertThatThrownBy(() -> provider.parseAccessToken(token(
                properties.getIssuer(), properties.getAudience(), null, "ROLE_USER", true,
                Jwts.SIG.RS256
        )).block()).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTokenWithoutExpiration() {
        assertThatThrownBy(() -> provider.parseAccessToken(token(
                properties.getIssuer(), properties.getAudience(), "AUTH_USER", "ROLE_USER", false,
                Jwts.SIG.RS256
        )).block()).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsAlgorithmOtherThanRs256() {
        assertThatThrownBy(() -> provider.parseAccessToken(token(
                properties.getIssuer(), properties.getAudience(), "AUTH_USER", "ROLE_USER", true,
                Jwts.SIG.RS512
        )).block()).isInstanceOf(JwtException.class);
    }

    private String token(
            String issuer,
            String audience,
            String userCode,
            String role,
            boolean expires,
            io.jsonwebtoken.security.SecureDigestAlgorithm<java.security.PrivateKey, java.security.PublicKey> algorithm
    ) {
        var builder = Jwts.builder()
                .header().keyId("test-key").and()
                .id(UUID.randomUUID().toString())
                .subject("accessToken")
                .issuer(issuer)
                .claim("aud", audience)
                .claim("userCode", userCode)
                .claim("userName", "user")
                .claim("role", role)
                .issuedAt(new Date())
                .signWith(keyPair.getPrivate(), algorithm);
        if (expires) {
            builder.expiration(new Date(System.currentTimeMillis() + 60_000));
        }
        return builder.compact();
    }
}
