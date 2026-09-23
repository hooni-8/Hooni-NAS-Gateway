package org.hooni.gateway.filters.routing;

import org.hooni.gateway.GatewayConsts;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.util.List;

/**
 * Gateway가 검증한 JWT와 권한만 하위 API로 전달한다.
 * 익명 요청에서는 클라이언트가 보낸 Authorization/x-authority 헤더를 제거한다.
 */
@Component
public class CustomTokenRelayGatewayFilterFactory
        extends AbstractGatewayFilterFactory<CustomTokenRelayGatewayFilterFactory.Config> {

    public static class Config {
        private boolean forwardCookies;

        public boolean isForwardCookies() {
            return forwardCookies;
        }

        public void setForwardCookies(boolean forwardCookies) {
            this.forwardCookies = forwardCookies;
        }
    }

    public CustomTokenRelayGatewayFilterFactory() {
        super(Config.class);
    }

    public GatewayFilter apply() {
        return apply(new Config());
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> exchange.getPrincipal()
                .filter(Authentication.class::isInstance)
                .cast(Authentication.class)
                .filter(Authentication::isAuthenticated)
                .map(authentication -> relayAuthentication(exchange, authentication, config))
                .defaultIfEmpty(removeTrustedHeaders(exchange, config))
                .flatMap(chain::filter);
    }

    private ServerWebExchange relayAuthentication(
            ServerWebExchange exchange,
            Authentication authentication,
            Config config
    ) {
        String jwtToken = String.valueOf(authentication.getCredentials());
        List<String> authorities = authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .toList();

        return exchange.mutate()
                .request(request -> request.headers(headers -> {
                    // 클라이언트가 보낸 권한 헤더를 신뢰하지 않고 Gateway가 검증한 값으로 교체한다.
                    headers.remove(GatewayConsts.X_AUTHORITY_HEADER);
                    headers.setBearerAuth(jwtToken);
                    if (!authorities.isEmpty()) {
                        headers.put(GatewayConsts.X_AUTHORITY_HEADER, authorities);
                    }
                    removeCookiesUnlessAllowed(headers, config);
                }))
                .build();
    }

    private ServerWebExchange removeTrustedHeaders(ServerWebExchange exchange, Config config) {
        return exchange.mutate()
                .request(request -> request.headers(headers -> {
                    // 인증되지 않은 요청이 내부 API에 신뢰 헤더를 위조해 전달하지 못하게 제거한다.
                    headers.remove(GatewayConsts.X_AUTHORITY_HEADER);
                    headers.remove("Authorization");
                    removeCookiesUnlessAllowed(headers, config);
                }))
                .build();
    }

    private void removeCookiesUnlessAllowed(HttpHeaders headers, Config config) {
        if (!config.isForwardCookies()) {
            // 일반 API에는 인증 쿠키를 포함한 브라우저 Cookie 전체를 전달하지 않는다.
            // Gateway가 검증해 만든 Authorization/x-authority만 내부 인증 정보로 사용한다.
            headers.remove(HttpHeaders.COOKIE);
        }
    }
}
