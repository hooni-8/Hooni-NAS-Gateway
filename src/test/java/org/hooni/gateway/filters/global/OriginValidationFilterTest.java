package org.hooni.gateway.filters.global;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.hooni.gateway.common.response.GatewayErrorResponseWriter;
import org.hooni.gateway.properties.CorsProperties;
import org.hooni.gateway.properties.AccessProperties;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class OriginValidationFilterTest {

    @Test
    void rejectsUnsafeRequestFromUnknownOrigin() {
        CorsProperties properties = new CorsProperties();
        properties.setAllowedOrigin(List.of("https://app.example.com"));
        OriginValidationFilter filter = new OriginValidationFilter(
                properties,
                new AccessProperties(),
                new GatewayErrorResponseWriter(new ObjectMapper())
        );
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/auth/login")
                        .header("Origin", "https://evil.example")
                        .build()
        );
        AtomicBoolean continued = new AtomicBoolean(false);
        WebFilterChain chain = ignored -> {
            continued.set(true);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(continued).isFalse();
    }

    @Test
    void allowsConfiguredOrigin() {
        CorsProperties properties = new CorsProperties();
        properties.setAllowedOrigin(List.of("https://app.example.com"));
        OriginValidationFilter filter = new OriginValidationFilter(
                properties,
                new AccessProperties(),
                new GatewayErrorResponseWriter(new ObjectMapper())
        );
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/auth/login")
                        .header("Origin", "https://app.example.com")
                        .build()
        );
        AtomicBoolean continued = new AtomicBoolean(false);

        filter.filter(exchange, ignored -> {
            continued.set(true);
            return Mono.empty();
        }).block();

        assertThat(continued).isTrue();
    }

    @Test
    void rejectsUnsafeCookieRequestWithoutOrigin() {
        CorsProperties properties = new CorsProperties();
        properties.setAllowedOrigin(List.of("https://app.example.com"));
        OriginValidationFilter filter = new OriginValidationFilter(
                properties,
                new AccessProperties(),
                new GatewayErrorResponseWriter(new ObjectMapper())
        );
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/auth/refresh")
                        .cookie(new org.springframework.http.HttpCookie("refreshToken", "token"))
                        .build()
        );
        AtomicBoolean continued = new AtomicBoolean(false);

        filter.filter(exchange, ignored -> {
            continued.set(true);
            return Mono.empty();
        }).block();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(continued).isFalse();
    }

    @Test
    void allowsServerRequestWithoutOriginWhenItHasNoAuthenticationCookie() {
        CorsProperties properties = new CorsProperties();
        properties.setAllowedOrigin(List.of("https://app.example.com"));
        OriginValidationFilter filter = new OriginValidationFilter(
                properties,
                new AccessProperties(),
                new GatewayErrorResponseWriter(new ObjectMapper())
        );
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/jobs")
                        .header("Authorization", "Bearer server-token")
                        .build()
        );
        AtomicBoolean continued = new AtomicBoolean(false);

        filter.filter(exchange, ignored -> {
            continued.set(true);
            return Mono.empty();
        }).block();

        assertThat(continued).isTrue();
    }
}
