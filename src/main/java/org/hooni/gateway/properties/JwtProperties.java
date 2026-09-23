package org.hooni.gateway.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.AssertTrue;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Auth API가 발급한 JWT를 JWKS 공개키로 검증하기 위한 설정이다. */
@Data
@Validated
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    @NotBlank
    private String issuer = "hooni-template-auth";
    @NotBlank
    private String audience = "hooni-template-api";
    @NotBlank
    @Pattern(regexp = "RS256")
    private String algorithm = "RS256";
    private String jwkSetUri;
    /** 테스트나 폐쇄망 배포에서 사용할 Base64 X.509 공개키. 일반 배포는 JWKS URI를 사용한다. */
    private String publicKey;

    @AssertTrue(message = "exactly one of jwk-set-uri or public-key must be configured")
    public boolean isVerificationSourceConfigured() {
        return isBlank(jwkSetUri) != isBlank(publicKey);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
