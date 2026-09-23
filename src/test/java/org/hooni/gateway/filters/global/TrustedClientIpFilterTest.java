package org.hooni.gateway.filters.global;

import org.hooni.gateway.GatewayConsts;
import org.hooni.gateway.properties.ProxyProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicReference;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TrustedClientIpFilterTest {

    @Test
    void replacesClientSuppliedIpWithRemoteAddress() {
        TrustedClientIpFilter filter = new TrustedClientIpFilter(new ProxyProperties());
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/auth/session")
                        .remoteAddress(new InetSocketAddress("192.0.2.10", 12345))
                        .header(GatewayConsts.X_CLIENT_IP_HEADER, "203.0.113.99")
                        .build()
        );
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        filter.filter(exchange, filtered -> {
            forwarded.set(filtered);
            return Mono.empty();
        }).block();

        assertThat(forwarded.get().getRequest().getHeaders()
                .getFirst(GatewayConsts.X_CLIENT_IP_HEADER)).isEqualTo("192.0.2.10");
    }

    @Test
    void usesForwardedClientIpOnlyWhenDirectPeerIsTrusted() {
        ProxyProperties properties = new ProxyProperties();
        properties.setTrustedAddresses(List.of("10.0.0.0/8"));
        TrustedClientIpFilter filter = new TrustedClientIpFilter(properties);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/auth/login")
                        .remoteAddress(new InetSocketAddress("10.0.0.10", 12345))
                        .header("X-Forwarded-For", "198.51.100.20, 10.0.0.9")
                        .build()
        );
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        filter.filter(exchange, filtered -> {
            forwarded.set(filtered);
            return Mono.empty();
        }).block();

        assertThat(forwarded.get().getRequest().getHeaders()
                .getFirst(GatewayConsts.X_CLIENT_IP_HEADER)).isEqualTo("198.51.100.20");
    }

    @Test
    void ignoresForwardedHeaderFromUntrustedPeer() {
        ProxyProperties properties = new ProxyProperties();
        properties.setTrustedAddresses(List.of("10.0.0.0/8"));
        TrustedClientIpFilter filter = new TrustedClientIpFilter(properties);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/auth/login")
                        .remoteAddress(new InetSocketAddress("192.0.2.10", 12345))
                        .header("X-Forwarded-For", "198.51.100.20")
                        .build()
        );
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        filter.filter(exchange, filtered -> {
            forwarded.set(filtered);
            return Mono.empty();
        }).block();

        assertThat(forwarded.get().getRequest().getHeaders()
                .getFirst(GatewayConsts.X_CLIENT_IP_HEADER)).isEqualTo("192.0.2.10");
        assertThat(forwarded.get().getRequest().getHeaders()
                .getFirst("X-Forwarded-For")).isEqualTo("192.0.2.10");
    }

    @Test
    void removesUntrustedForwardedMetadata() {
        TrustedClientIpFilter filter = new TrustedClientIpFilter(new ProxyProperties());
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/profile")
                        .remoteAddress(new InetSocketAddress("192.0.2.10", 12345))
                        .header("Forwarded", "for=203.0.113.99;proto=https")
                        .header("X-Forwarded-Host", "attacker.example")
                        .header("X-Forwarded-Proto", "https")
                        .header("X-Forwarded-Port", "443")
                        .build()
        );
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        filter.filter(exchange, filtered -> {
            forwarded.set(filtered);
            return Mono.empty();
        }).block();

        assertThat(forwarded.get().getRequest().getHeaders().getFirst("Forwarded")).isNull();
        assertThat(forwarded.get().getRequest().getHeaders().getFirst("X-Forwarded-Host")).isNull();
        assertThat(forwarded.get().getRequest().getHeaders().getFirst("X-Forwarded-Proto")).isNull();
        assertThat(forwarded.get().getRequest().getHeaders().getFirst("X-Forwarded-Port")).isNull();
        assertThat(forwarded.get().getRequest().getHeaders().getFirst("X-Forwarded-For"))
                .isEqualTo("192.0.2.10");
    }
}
