package org.hooni.gateway.filters.jwt;

import lombok.RequiredArgsConstructor;
import org.hooni.gateway.common.response.GatewayErrorResponseWriter;
import org.hooni.gateway.common.code.StatusCode;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** 인증되지 않은 사용자가 보호 경로를 호출했을 때 일관된 401 JSON 응답을 작성한다. */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final GatewayErrorResponseWriter errorResponseWriter;

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {

        return errorResponseWriter.write(exchange.getResponse(), HttpStatus.UNAUTHORIZED, StatusCode.UNAUTHORIZED);
    }
}
