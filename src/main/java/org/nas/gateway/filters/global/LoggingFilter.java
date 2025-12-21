package org.nas.gateway.filters.global;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_REQUEST_URL_ATTR;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;

@Slf4j
@Component
public class LoggingFilter implements GlobalFilter, Ordered {
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        long start = System.currentTimeMillis();
        Route route = exchange.getAttribute(GATEWAY_ROUTE_ATTR);

        log.debug("Start routing {} - {}", route.getId(), exchange.getRequest().getURI(), start);

        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            String traceId = null;
            List<String> header = exchange.getResponse().getHeaders().get("traceId");
            if(header != null) {
                traceId = header.stream().map(id -> String.valueOf(id)).collect(Collectors.joining());
            }
            log.info("[{} => {}] {} => {} {} {}ms", exchange.getRequest().getId(), traceId, route.getId(), exchange.getRequest().getURI(), exchange.getAttribute(GATEWAY_REQUEST_URL_ATTR), (System.currentTimeMillis() - start));
        }));

    }
}