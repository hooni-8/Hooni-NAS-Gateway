package org.hooni.gateway.filters.jwt;

import lombok.RequiredArgsConstructor;
import org.hooni.gateway.common.response.GatewayErrorResponseWriter;
import org.hooni.gateway.common.code.StatusCode;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** 인증은 되었지만 필요한 권한이 없는 요청에 일관된 403 JSON 응답을 작성한다. */
@Component
@RequiredArgsConstructor
public class JwtAccessDeniedHandler implements ServerAccessDeniedHandler {

    private final GatewayErrorResponseWriter errorResponseWriter;

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        return errorResponseWriter.write(exchange.getResponse(), HttpStatus.FORBIDDEN, StatusCode.FORBIDDEN);
    }
}
