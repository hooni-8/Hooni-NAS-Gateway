package org.hooni.gateway.properties;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

/** 라우팅 대상 서비스의 scheme, host, port, context를 URL로 조립하는 공통 설정이다. */
@Data
public class CommonUrlProperties {
    @NotBlank
    @Pattern(regexp = "https?", flags = Pattern.Flag.CASE_INSENSITIVE)
    protected String scheme;
    @NotBlank
    protected String host;
    @NotBlank
    protected String context;
    @Min(0)
    @Max(65535)
    protected int port;

    public void setContext(String context) {
        this.context = normalizePath(context);
    }

    /** 실제 라우팅 대상의 context를 제외한 base URL을 반환한다. */
    public String getHost() {
        return buildUri("").toString();
    }

    public String getUrl() {
        return getURI().toString();
    }

    public URI getURI() {
        return buildUri(context).toUri();
    }

    protected void validate() {
        if (scheme == null || scheme.isBlank()) {
            throw new IllegalStateException("Route scheme must not be blank");
        }
        if (host == null || host.isBlank()) {
            throw new IllegalStateException("Route host must not be blank");
        }
        if (port < 0 || port > 65535) {
            throw new IllegalStateException("Route port must be between 0 and 65535");
        }
    }

    protected static String normalizePath(String value) {
        if (value == null || value.isBlank() || "/".equals(value.trim())) {
            return "";
        }
        String normalized = value.trim().replaceAll("^/+|/+$", "");
        return normalized.isEmpty() ? "" : "/" + normalized;
    }

    private UriComponents buildUri(String path) {
        validate();
        UriComponentsBuilder builder = UriComponentsBuilder.newInstance()
                .scheme(scheme)
                .host(host)
                .path(path);

        boolean defaultPort = port == 0
                || ("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443);
        if (!defaultPort) {
            builder.port(port);
        }
        return builder.build();
    }
}
