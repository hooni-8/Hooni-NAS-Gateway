package org.hooni.gateway.filters.global;

import lombok.RequiredArgsConstructor;
import org.hooni.gateway.common.response.GatewayErrorResponseWriter;
import org.hooni.gateway.common.code.StatusCode;
import org.hooni.gateway.properties.CorsProperties;
import org.hooni.gateway.properties.AccessProperties;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * 브라우저의 상태 변경 요청이 허용된 Origin에서 왔는지 검사한다.
 * Origin이 없는 서버 간 요청은 인증 쿠키가 없을 때만 통과시키고 GET/HEAD/OPTIONS는 항상 안전 메서드로 본다.
 */
@Component
@RequiredArgsConstructor
public class OriginValidationFilter implements WebFilter, Ordered {
    private static final Set<HttpMethod> SAFE_METHODS = Set.of(
            HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS
    );

    private final CorsProperties corsProperties;
    private final AccessProperties accessProperties;
    private final GatewayErrorResponseWriter errorResponseWriter;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        HttpMethod method = exchange.getRequest().getMethod();
        String origin = exchange.getRequest().getHeaders().getOrigin();
        boolean hasAuthenticationCookie = exchange.getRequest().getCookies()
                .containsKey(accessProperties.getAccessTokenCookieName())
                || exchange.getRequest().getCookies()
                .containsKey(accessProperties.getRefreshTokenCookieName());
        boolean invalidOrigin = origin != null
                && !corsProperties.getAllowedOrigin().contains(origin);
        boolean missingOriginForCookieRequest = hasAuthenticationCookie && origin == null;

        if (!SAFE_METHODS.contains(method)
                && (invalidOrigin || missingOriginForCookieRequest)) {
            return errorResponseWriter.write(
                    exchange.getResponse(),
                    HttpStatus.FORBIDDEN,
                    StatusCode.INVALID_ORIGIN
            );
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 20;
    }
}
