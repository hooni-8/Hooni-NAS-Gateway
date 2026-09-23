package org.hooni.gateway.properties;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.util.unit.DataSize;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GatewayPropertiesValidationTest {

    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    @org.springframework.boot.context.properties.EnableConfigurationProperties(AccessProperties.class)
    static class BindingConfiguration {}

    @Test
    void startupFailsWhenPublicEndpointHasNoMethod() {
        new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                .withUserConfiguration(BindingConfiguration.class)
                .withPropertyValues("application.security.public-endpoints[0].path=/auth/login")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void startupBindsValidEndpointAndSize() {
        new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                .withUserConfiguration(BindingConfiguration.class)
                .withPropertyValues("application.security.public-endpoints[0].path=/auth/login",
                        "application.security.public-endpoints[0].method=POST",
                        "application.security.max-request-size=2MB")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(AccessProperties.class).getMaxRequestSize())
                            .isEqualTo(DataSize.ofMegabytes(2));
                });
    }

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void rejectsDuplicatePublicEndpointAndZeroRequestSize() {
        AccessProperties.PublicEndpoint first = endpoint(HttpMethod.POST, "/auth/login");
        AccessProperties.PublicEndpoint duplicate = endpoint(HttpMethod.POST, "/auth/login");
        AccessProperties properties = new AccessProperties();
        properties.setPublicEndpoints(List.of(first, duplicate));
        properties.setMaxRequestSize(DataSize.ofBytes(0));

        assertThat(validator.validate(properties))
                .extracting(violation -> violation.getMessage())
                .contains(
                        "public-endpoints must not contain duplicate method/path pairs",
                        "max-request-size must be between 1 byte and 50 MB"
                );
    }

    @Test
    void rejectsRequestSizeAboveBufferingSafetyLimit() {
        AccessProperties properties = new AccessProperties();
        properties.setPublicEndpoints(List.of(endpoint(HttpMethod.POST, "/auth/login")));
        properties.setMaxRequestSize(DataSize.ofMegabytes(51));

        assertThat(validator.validate(properties))
                .extracting(violation -> violation.getMessage())
                .contains("max-request-size must be between 1 byte and 50 MB");
    }

    @Test
    void rejectsWildcardCorsConfiguration() {
        CorsProperties properties = new CorsProperties();
        properties.setAllowedOrigin(List.of("*"));
        properties.setAllowedMethods(List.of("*"));
        properties.setAllowedHeaders(List.of("*"));
        properties.setExposedHeaders(List.of("X-Request-ID"));

        assertThat(validator.validate(properties))
                .extracting(violation -> violation.getMessage())
                .contains(
                        "allowed-origin must contain only explicit http/https origins without paths",
                        "allowed-methods must contain explicit valid HTTP methods, not *",
                        "allowed-headers must not contain *"
                );
    }

    @Test
    void reportsNullOriginAndTrustedAddressAsValidationErrors() {
        CorsProperties cors = new CorsProperties();
        cors.setAllowedOrigin(new java.util.ArrayList<>(java.util.Arrays.asList((String) null)));
        cors.setAllowedMethods(List.of("GET"));
        cors.setAllowedHeaders(List.of("Authorization"));
        cors.setExposedHeaders(List.of("X-Request-ID"));
        ProxyProperties proxy = new ProxyProperties();
        proxy.setTrustedAddresses(null);

        assertThat(validator.validate(cors)).isNotEmpty();
        assertThat(validator.validate(proxy)).isNotEmpty();
    }

    private AccessProperties.PublicEndpoint endpoint(HttpMethod method, String path) {
        AccessProperties.PublicEndpoint endpoint = new AccessProperties.PublicEndpoint();
        endpoint.setMethod(method);
        endpoint.setPath(path);
        return endpoint;
    }
}
