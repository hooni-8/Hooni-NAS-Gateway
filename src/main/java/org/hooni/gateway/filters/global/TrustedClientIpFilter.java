package org.hooni.gateway.filters.global;

import org.hooni.gateway.GatewayConsts;
import org.hooni.gateway.properties.ProxyProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Collections;

/**
 * 신뢰 프록시 체인을 기준으로 실제 클라이언트 IP를 계산하고 위조 가능한 전달 헤더를 정제한다.
 * 운영 환경에서는 application.proxy.trusted-addresses에 실제 Ingress CIDR을 등록해야 한다.
 */
@Component
public class TrustedClientIpFilter implements GlobalFilter, Ordered {
    private static final String FORWARDED = "Forwarded";
    private static final String X_FORWARDED_FOR = "X-Forwarded-For";
    private static final List<String> FORWARDED_HEADERS = List.of(
            FORWARDED,
            X_FORWARDED_FOR,
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Forwarded-Port",
            "X-Forwarded-Prefix",
            "X-Real-IP"
    );

    private final List<CidrMatcher> trustedProxies;

    public TrustedClientIpFilter(ProxyProperties proxyProperties) {
        this.trustedProxies = Optional.ofNullable(proxyProperties.getTrustedAddresses())
                .orElseGet(Collections::emptyList)
                .stream()
                .filter(address -> address != null && !address.isBlank())
                .map(CidrMatcher::new)
                .toList();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        InetSocketAddress remoteAddress = exchange.getRequest().getRemoteAddress();
        String remoteIp = getRemoteIp(remoteAddress);
        String clientIp = resolveClientIp(exchange.getRequest().getHeaders(), remoteIp);

        ServerWebExchange sanitized = exchange.mutate()
                .request(request -> request.headers(headers -> {
                    headers.remove(GatewayConsts.X_CLIENT_IP_HEADER);
                    // 외부에서 전달한 Forwarded 계열 헤더는 하위 API가 신뢰하지 않도록 제거한다.
                    // 검증된 clientIp만 새 X-Forwarded-For와 X-Client-IP로 전달한다.
                    FORWARDED_HEADERS.forEach(headers::remove);
                    headers.set(X_FORWARDED_FOR, clientIp);
                    headers.set(GatewayConsts.X_CLIENT_IP_HEADER, clientIp);
                }))
                .build();

        return chain.filter(sanitized);
    }

    private String resolveClientIp(HttpHeaders headers, String remoteIp) {
        // 전달 헤더는 요청을 직접 보낸 주소가 신뢰 프록시일 때만 사용한다.
        if (!isTrustedProxy(remoteIp)) {
            return remoteIp;
        }

        List<String> forwardedAddresses = headers.getOrEmpty(X_FORWARDED_FOR).stream()
                .flatMap(value -> Arrays.stream(value.split(",")))
                .map(String::trim)
                .filter(this::isIpLiteral)
                .toList();

        // 오른쪽부터 신뢰 프록시를 제거하고 최초의 비신뢰 주소를 실제 클라이언트로 본다.
        for (int index = forwardedAddresses.size() - 1; index >= 0; index--) {
            String candidate = forwardedAddresses.get(index);
            if (!isTrustedProxy(candidate)) {
                return candidate;
            }
        }
        return remoteIp;
    }

    private String getRemoteIp(InetSocketAddress remoteAddress) {
        return Optional.ofNullable(remoteAddress)
                .map(InetSocketAddress::getAddress)
                .map(address -> address.getHostAddress())
                .orElse("unknown");
    }

    private boolean isTrustedProxy(String address) {
        if (!isIpLiteral(address)) {
            return false;
        }
        return trustedProxies.stream().anyMatch(matcher -> matcher.matches(address));
    }

    private boolean isIpLiteral(String address) {
        return address != null
                && (address.contains(".") || address.contains(":"))
                && address.matches("[0-9a-fA-F:.]+");
    }

    private static final class CidrMatcher {
        private final byte[] network;
        private final int prefixLength;

        private CidrMatcher(String value) {
            try {
                String[] parts = value.trim().split("/", 2);
                this.network = InetAddress.getByName(parts[0]).getAddress();
                int maximumPrefix = network.length * 8;
                this.prefixLength = parts.length == 1
                        ? maximumPrefix
                        : Integer.parseInt(parts[1]);
                if (prefixLength < 0 || prefixLength > maximumPrefix) {
                    throw new IllegalArgumentException("Invalid trusted proxy CIDR: " + value);
                }
            } catch (UnknownHostException | NumberFormatException e) {
                throw new IllegalArgumentException("Invalid trusted proxy address: " + value, e);
            }
        }

        private boolean matches(String address) {
            try {
                byte[] candidate = InetAddress.getByName(address).getAddress();
                if (candidate.length != network.length) {
                    return false;
                }
                int fullBytes = prefixLength / 8;
                int remainingBits = prefixLength % 8;
                for (int index = 0; index < fullBytes; index++) {
                    if (candidate[index] != network[index]) {
                        return false;
                    }
                }
                if (remainingBits == 0) {
                    return true;
                }
                int mask = 0xFF << (8 - remainingBits);
                return (candidate[fullBytes] & mask) == (network[fullBytes] & mask);
            } catch (UnknownHostException e) {
                return false;
            }
        }
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}
