package org.hooni.gateway.filters.jwt;

import org.hooni.gateway.common.model.LoginStatus;
import org.hooni.gateway.properties.JwtProperties;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Mono;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Auth API의 JWKS 공개키로 Access Token을 검증하고 인증 정보를 변환한다. */
@Component
public class JwtTokenProvider {

    private static final String ACCESS_SUBJECT = "accessToken";

    private final JwtProperties properties;
    private final ReactiveJwtDecoder decoder;

    @Autowired
    public JwtTokenProvider(JwtProperties properties) {
        this(properties, createDecoder(properties));
    }

    JwtTokenProvider(JwtProperties properties, ReactiveJwtDecoder decoder) {
        this.properties = properties;
        this.decoder = decoder;
    }

    public Mono<LoginStatus> parseAccessToken(String token) {
        return decoder.decode(token).map(this::toLoginStatus);
    }

    private LoginStatus toLoginStatus(Jwt jwt) {
        if (!ACCESS_SUBJECT.equals(jwt.getSubject())) {
            throw new BadJwtException("Unexpected token subject");
        }
        if (!jwt.getAudience().contains(properties.getAudience())) {
            throw new BadJwtException("Unexpected token audience");
        }
        if (jwt.getId() == null || jwt.getId().isBlank()) {
            throw new BadJwtException("Token id is required");
        }
        if (jwt.getExpiresAt() == null) {
            throw new BadJwtException("Token expiration is required");
        }

        String userCode = requireTextClaim(jwt, "userCode");
        String role = requireTextClaim(jwt, "role");
        if (!role.matches("[A-Z][A-Z0-9_]{0,63}")) {
            throw new BadJwtException("Invalid role claim");
        }

        return LoginStatus.getSuccess(userCode, jwt.getClaimAsString("userName"), role);
    }

    private String requireTextClaim(Jwt jwt, String name) {
        String value = jwt.getClaimAsString(name);
        if (value == null || value.isBlank()) {
            throw new BadJwtException("Token claim is required: " + name);
        }
        return value;
    }

    private static ReactiveJwtDecoder createDecoder(JwtProperties properties) {
        NimbusReactiveJwtDecoder decoder;
        if (properties.getPublicKey() != null && !properties.getPublicKey().isBlank()) {
            decoder = NimbusReactiveJwtDecoder.withPublicKey(parsePublicKey(properties.getPublicKey()))
                    .signatureAlgorithm(SignatureAlgorithm.RS256)
                    .build();
        } else {
            decoder = NimbusReactiveJwtDecoder.withJwkSetUri(properties.getJwkSetUri())
                    .jwsAlgorithm(SignatureAlgorithm.RS256)
                    .build();
        }
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.getIssuer()));
        return decoder;
    }

    private static RSAPublicKey parsePublicKey(String value) {
        try {
            byte[] bytes = Base64.getDecoder().decode(value.replaceAll("\\s", ""));
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(bytes));
        } catch (Exception exception) {
            throw new IllegalArgumentException("jwt.public-key must be a Base64 X.509 RSA public key", exception);
        }
    }
}
