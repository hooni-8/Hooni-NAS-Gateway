package org.nas.gateway.filters.jwt;

import lombok.RequiredArgsConstructor;
import org.nas.gateway.common.response.GatewayErrorResponseWriter;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAccessDeniedHandler implements ServerAccessDeniedHandler {

    private final GatewayErrorResponseWriter errorResponseWriter;

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        return errorResponseWriter.write(exchange.getResponse(), HttpStatus.FORBIDDEN, "FORBIDDEN");
    }
}
