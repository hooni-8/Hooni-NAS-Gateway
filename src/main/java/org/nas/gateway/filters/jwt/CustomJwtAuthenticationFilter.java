package org.nas.gateway.filters.jwt;

import lombok.extern.slf4j.Slf4j;
import org.nas.gateway.properties.AccessProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.http.HttpCookie;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Optional;

@Slf4j
@Component
public class CustomJwtAuthenticationFilter implements WebFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        if (path.startsWith("/nas/api/v1/file/video/")) {
            return chain.filter(exchange);
        }

        String token = extractToken(exchange);

        if (token != null && jwtTokenProvider.validateAccessToken(token)) {

            Authentication auth =
                    new UsernamePasswordAuthenticationToken(
                            jwtTokenProvider.getAccessTokenUserCode(token),
                            token,
                            Collections.emptyList()
                    );

            SecurityContext context = new SecurityContextImpl(auth);

            return chain.filter(exchange)
                    .contextWrite(
                            ReactiveSecurityContextHolder.withSecurityContext(
                                    Mono.just(context)
                            )
                    );
        }

        return chain.filter(exchange);
    }

    private String extractToken(ServerWebExchange exchange) {
        return Optional.ofNullable(
                        exchange.getRequest().getCookies().getFirst("accessToken")
                )
                .map(HttpCookie::getValue)
                .orElse(null);
    }

}
