package org.hooni.gateway.filters.global;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

class LoggingFilterTest {

    @Test
    void replacesExternalRequestIdAndRelaysGeneratedId() {
        LoggingFilter filter = new LoggingFilter();
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/auth/session")
                        .header("X-Request-ID", "client-controlled-value")
                        .build()
        );
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        filter.filter(exchange, filtered -> {
            forwarded.set(filtered);
            return Mono.empty();
        }).block();

        String generatedId = forwarded.get().getRequest().getHeaders().getFirst("X-Request-ID");
        assertThat(generatedId)
                .isNotBlank()
                .isNotEqualTo("client-controlled-value");
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Request-ID"))
                .isEqualTo(generatedId);
    }

    @Test
    void removesQueryAndUserInfoFromLoggedTargetUrl() {
        URI target = URI.create("http://user:password@auth-api:8080/auth/session?token=secret#fragment");

        assertThat(LoggingFilter.sanitizeTargetUrl(target))
                .isEqualTo("http://auth-api:8080/auth/session");
    }
}
