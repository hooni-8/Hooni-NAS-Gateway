package org.hooni.gateway.filters.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hooni.gateway.common.model.LoginStatus;
import org.hooni.gateway.properties.AccessProperties;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

/**
 * 요청의 Bearer Token 또는 accessToken 쿠키를 검증해 현재 Reactor Context에 인증 정보를 넣는다.
 * Bearer Token을 우선하며 인증 실패 응답은 SecurityWebFilterChain에 위임한다.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CustomJwtAuthenticationFilter implements WebFilter {
    private final JwtTokenProvider jwtTokenProvider;
    private final AccessProperties accessProperties;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);
        if (token == null) {
            return chain.filter(exchange);
        }

        return jwtTokenProvider.parseAccessToken(token)
                .flatMap(loginStatus -> authenticatedChain(exchange, chain, token, loginStatus))
                .onErrorResume(JwtException.class, authenticationFailure -> {
                    log.debug("Access token validation failed: {}", authenticationFailure.getClass().getSimpleName());
                    return chain.filter(exchange);
                })
                .onErrorResume(IllegalArgumentException.class, authenticationFailure -> {
                    log.debug("Access token validation failed: {}", authenticationFailure.getClass().getSimpleName());
                    return chain.filter(exchange);
                });
    }

    private Mono<Void> authenticatedChain(
            ServerWebExchange exchange,
            WebFilterChain chain,
            String token,
            LoginStatus loginStatus
    ) {
        List<SimpleGrantedAuthority> authorities = loginStatus.getRole() == null
                ? List.of()
                : List.of(new SimpleGrantedAuthority(loginStatus.getRole()));

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        loginStatus.getUserCode(),
                        token,
                        authorities
                );

        return chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                        Mono.just(new SecurityContextImpl(authentication))
                ));
    }

    private String extractToken(ServerWebExchange exchange) {
        // 명시적으로 전달된 Bearer Token을 우선한다. 서버 간 호출에서 브라우저의
        // 오래된 쿠키가 유효한 Authorization 헤더를 덮어쓰지 않도록 Auth API와 순서를 맞춘다.
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String bearerToken = authorization.substring(7).trim();
            if (!bearerToken.isBlank()) {
                return bearerToken;
            }
        }

        // Bearer Token이 없는 브라우저 요청은 HttpOnly 쿠키를 사용한다.
        return Optional.ofNullable(
                        exchange.getRequest().getCookies().getFirst(
                                accessProperties.getAccessTokenCookieName()
                        )
                )
                .map(HttpCookie::getValue)
                .filter(token -> !token.isBlank())
                .orElse(null);
    }
}
