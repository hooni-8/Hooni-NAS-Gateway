package org.nas.gateway.filters.jwt;

import lombok.extern.slf4j.Slf4j;
import org.nas.gateway.properties.AccessProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.http.HttpCookie;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;

@Slf4j
@Component
public class CustomJwtAuthenticationFilter implements WebFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private AccessProperties accessProperties;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (isPreflightOrExcludedPath(request)) {
            return chain.filter(exchange);
        }

        String token = extractToken(request);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            return authenticateAndContinue(exchange, chain, token);
        } else {
            return respondUnauthorized(exchange.getResponse());
        }
    }

    private boolean isPreflightOrExcludedPath(ServerHttpRequest request) {
        if (CorsUtils.isPreFlightRequest(request)) return true;

        String path = request.getPath().value();
        return Arrays.stream(accessProperties.getExcludesArray())
                .anyMatch(path::startsWith);
    }

    private String extractToken(ServerHttpRequest request) {
        return Optional.ofNullable(request.getCookies().getFirst("accessToken"))
                .map(HttpCookie::getValue)
                .orElse(null);
    }

    private Mono<Void> authenticateAndContinue(ServerWebExchange exchange, WebFilterChain chain, String token) {
        String accessSubject = jwtTokenProvider.getAccessSubject(token);
        Authentication authentication = new UsernamePasswordAuthenticationToken(accessSubject, token, Collections.emptyList());
        SecurityContext context = new SecurityContextImpl(authentication);

        return chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(context)));
    }

    private Mono<Void> respondUnauthorized(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().add("Access-Control-Allow-Origin", "*");
        response.getHeaders().add("Access-Control-Allow-Headers", "Authorization, Content-Type");
        response.getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

        String body = "{\"message\":\"Unauthorized\"}";
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}
