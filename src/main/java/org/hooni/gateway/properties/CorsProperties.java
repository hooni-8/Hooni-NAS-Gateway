package org.hooni.gateway.properties;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** 브라우저에서 쿠키를 포함해 Gateway를 호출할 수 있는 Origin 목록이다. */
@Data
@Validated
@ConfigurationProperties(prefix = "application.cors")
public class CorsProperties {
    @NotEmpty
    private List<@NotBlank String> allowedOrigin;

    @NotEmpty
    private List<@NotBlank String> allowedMethods;

    @NotEmpty
    private List<@NotBlank String> allowedHeaders;

    @NotEmpty
    private List<@NotBlank String> exposedHeaders;

    @AssertTrue(message = "allowed-origin must contain only explicit http/https origins without paths")
    public boolean isAllowedOriginValid() {
        if (allowedOrigin == null) {
            return true;
        }
        return allowedOrigin.stream().allMatch(this::isOrigin);
    }

    @AssertTrue(message = "allowed-methods must contain explicit valid HTTP methods, not *")
    public boolean isAllowedMethodsValid() {
        if (allowedMethods == null) {
            return true;
        }
        Set<String> supported = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
        return allowedMethods.stream()
                .allMatch(method -> method != null && supported.contains(method.toUpperCase(Locale.ROOT)));
    }

    @AssertTrue(message = "allowed-headers must not contain *")
    public boolean isAllowedHeadersValid() {
        return allowedHeaders == null || allowedHeaders.stream().noneMatch("*"::equals);
    }

    private boolean isOrigin(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        try {
            URI uri = URI.create(value);
            return ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                    && uri.getHost() != null
                    && (uri.getPath() == null || uri.getPath().isEmpty())
                    && uri.getQuery() == null
                    && uri.getFragment() == null;
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }
}
