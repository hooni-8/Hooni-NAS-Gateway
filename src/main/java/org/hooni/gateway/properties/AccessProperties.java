package org.hooni.gateway.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.convert.DataSizeUnit;
import org.springframework.util.unit.DataSize;
import org.springframework.util.unit.DataUnit;
import org.springframework.http.HttpMethod;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;

/** Gateway 인증 없이 Auth API까지 전달할 공개 요청 경로를 관리한다. */
@Data
@Validated
@ConfigurationProperties(prefix = "application.security")
public class AccessProperties {
    private static final long MAX_REQUEST_SIZE_BYTES = DataSize.ofMegabytes(50).toBytes();

    @NotNull
    @DataSizeUnit(DataUnit.MEGABYTES)
    private DataSize maxRequestSize = DataSize.ofMegabytes(2);

    @NotBlank
    private String accessTokenCookieName = "accessToken";

    @NotBlank
    private String refreshTokenCookieName = "refreshToken";

    // permitAll은 Gateway 인증 요구만 해제한다.
    // 실제 로그인/갱신 검증 책임은 라우팅 대상인 Auth API에 남아 있다.
    @Valid
    @NotEmpty
    private List<@NotNull @Valid PublicEndpoint> publicEndpoints = new ArrayList<>();

    @AssertTrue(message = "public-endpoints must not contain duplicate method/path pairs")
    public boolean isPublicEndpointsUnique() {
        return publicEndpoints == null || publicEndpoints.stream()
                .filter(java.util.Objects::nonNull)
                .map(endpoint -> endpoint.method + " " + endpoint.path)
                .distinct()
                .count() == publicEndpoints.size();
    }

    @AssertTrue(message = "max-request-size must be between 1 byte and 50 MB")
    public boolean isMaxRequestSizePositive() {
        return maxRequestSize == null
                || maxRequestSize.toBytes() > 0 && maxRequestSize.toBytes() <= MAX_REQUEST_SIZE_BYTES;
    }

    /** 공개 경로와 허용할 HTTP Method를 하나의 규칙으로 묶는다. */
    @Data
    public static class PublicEndpoint {
        @NotNull
        private HttpMethod method;

        @NotBlank
        @jakarta.validation.constraints.Pattern(regexp = "^/.*", message = "must start with /")
        private String path;
    }
}
