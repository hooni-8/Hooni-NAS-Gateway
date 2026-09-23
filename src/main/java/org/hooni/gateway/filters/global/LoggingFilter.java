package org.hooni.gateway.filters.global;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_REQUEST_URL_ATTR;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.UUID;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;

/**
 * 라우트 ID, 요청 경로, 대상 URL, 상태 코드와 처리 시간을 기록한다.
 * query parameter와 인증 토큰은 로그에 남기지 않는다.
 */
@Slf4j
@Component
public class LoggingFilter implements WebFilter, Ordered {
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        long start = System.currentTimeMillis();
        String requestId = UUID.randomUUID().toString();
        String requestPath = exchange.getRequest().getPath().value();

        // 외부 입력값 대신 Gateway가 생성한 ID를 사용해 로그 위조를 막고 하위 API까지 전달한다.
        ServerWebExchange requestIdExchange = exchange.mutate()
                .request(request -> request.headers(headers -> headers.set("X-Request-ID", requestId)))
                .build();
        requestIdExchange.getResponse().getHeaders().set("X-Request-ID", requestId);
        log.debug("Start request {} - {}", requestId, requestPath);

        return chain.filter(requestIdExchange).doFinally(signal -> {
            Route route = requestIdExchange.getAttribute(GATEWAY_ROUTE_ATTR);
            String routeId = route == null ? "local-or-unmatched" : route.getId();
            log.info(
                    "[{}] {} {} {} => {} status={} signal={} {}ms",
                    requestId,
                    requestIdExchange.getRequest().getMethod(),
                    routeId,
                    requestPath,
                    sanitizeTargetUrl(requestIdExchange.getAttribute(GATEWAY_REQUEST_URL_ATTR)),
                    requestIdExchange.getResponse().getStatusCode(),
                    signal,
                    System.currentTimeMillis() - start
            );
        });

    }

    static String sanitizeTargetUrl(URI targetUrl) {
        if (targetUrl == null) {
            return "-";
        }
        StringBuilder sanitized = new StringBuilder();
        if (targetUrl.getScheme() != null) {
            sanitized.append(targetUrl.getScheme()).append("://");
        }
        if (targetUrl.getHost() != null) {
            sanitized.append(targetUrl.getHost());
        }
        if (targetUrl.getPort() >= 0) {
            sanitized.append(':').append(targetUrl.getPort());
        }
        if (targetUrl.getRawPath() != null) {
            sanitized.append(targetUrl.getRawPath());
        }
        return sanitized.toString();
    }
}
