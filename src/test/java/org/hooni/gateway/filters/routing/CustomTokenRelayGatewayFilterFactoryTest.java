package org.hooni.gateway.filters.routing;

import org.hooni.gateway.GatewayConsts;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class CustomTokenRelayGatewayFilterFactoryTest {

    @Test
    void removesCookiesFromGeneralApiAndRelaysVerifiedAuthentication() {
        CustomTokenRelayGatewayFilterFactory factory = new CustomTokenRelayGatewayFilterFactory();
        CustomTokenRelayGatewayFilterFactory.Config config = new CustomTokenRelayGatewayFilterFactory.Config();
        config.setForwardCookies(false);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                "AUTH_USER", "verified-token", List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        ServerWebExchange exchange = MockServerWebExchange.from(
                        MockServerHttpRequest.get("/api/profile")
                                .header(HttpHeaders.COOKIE, "accessToken=secret; refreshToken=refresh")
                                .build()
                ).mutate()
                .principal(Mono.just(authentication))
                .build();
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        factory.apply(config).filter(exchange, filtered -> {
            forwarded.set(filtered);
            return Mono.empty();
        }).block();

        assertThat(forwarded.get().getRequest().getHeaders().getFirst(HttpHeaders.COOKIE)).isNull();
        assertThat(forwarded.get().getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer verified-token");
        assertThat(forwarded.get().getRequest().getHeaders().get(GatewayConsts.X_AUTHORITY_HEADER))
                .containsExactly("ROLE_USER");
    }

    @Test
    void keepsCookiesOnlyWhenRouteExplicitlyAllowsThem() {
        CustomTokenRelayGatewayFilterFactory factory = new CustomTokenRelayGatewayFilterFactory();
        CustomTokenRelayGatewayFilterFactory.Config config = new CustomTokenRelayGatewayFilterFactory.Config();
        config.setForwardCookies(true);
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/auth/refresh")
                        .header(HttpHeaders.COOKIE, "refreshToken=refresh")
                        .build()
        );
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        factory.apply(config).filter(exchange, filtered -> {
            forwarded.set(filtered);
            return Mono.empty();
        }).block();

        assertThat(forwarded.get().getRequest().getHeaders().getFirst(HttpHeaders.COOKIE))
                .isEqualTo("refreshToken=refresh");
    }
}
