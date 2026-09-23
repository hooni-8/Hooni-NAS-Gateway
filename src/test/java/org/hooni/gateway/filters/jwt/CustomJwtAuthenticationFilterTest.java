package org.hooni.gateway.filters.jwt;

import org.hooni.gateway.common.model.LoginStatus;
import org.hooni.gateway.properties.AccessProperties;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtException;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CustomJwtAuthenticationFilterTest {

    @Test
    void bearerTokenHasPriorityOverAccessTokenCookie() {
        JwtTokenProvider tokenProvider = mock(JwtTokenProvider.class);
        when(tokenProvider.parseAccessToken("bearer-token"))
                .thenReturn(Mono.just(LoginStatus.getSuccess("AUTH_USER", "user", "ROLE_USER")));
        CustomJwtAuthenticationFilter filter = new CustomJwtAuthenticationFilter(tokenProvider, new AccessProperties());
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/profile")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer bearer-token")
                        .cookie(new HttpCookie("accessToken", "cookie-token"))
                        .build()
        );
        AtomicReference<Authentication> authentication = new AtomicReference<>();

        filter.filter(exchange, filtered -> ReactiveSecurityContextHolder.getContext()
                .doOnNext(context -> authentication.set(context.getAuthentication()))
                .then()).block();

        assertThat(authentication.get()).isNotNull();
        assertThat(authentication.get().getCredentials()).isEqualTo("bearer-token");
        verify(tokenProvider).parseAccessToken("bearer-token");
    }

    @Test
    void invalidJwtContinuesAsAnonymousRequest() {
        JwtTokenProvider tokenProvider = mock(JwtTokenProvider.class);
        when(tokenProvider.parseAccessToken("invalid-token"))
                .thenReturn(Mono.error(new JwtException("invalid")));
        CustomJwtAuthenticationFilter filter = new CustomJwtAuthenticationFilter(tokenProvider, new AccessProperties());
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/auth/session")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token")
                        .build()
        );

        filter.filter(exchange, filtered -> ReactiveSecurityContextHolder.getContext().then()).block();

        verify(tokenProvider).parseAccessToken("invalid-token");
    }

    @Test
    void unexpectedFailureIsNotHiddenAsAuthenticationFailure() {
        JwtTokenProvider tokenProvider = mock(JwtTokenProvider.class);
        when(tokenProvider.parseAccessToken("valid-shape-token"))
                .thenReturn(Mono.error(new IllegalStateException("configuration failure")));
        CustomJwtAuthenticationFilter filter = new CustomJwtAuthenticationFilter(tokenProvider, new AccessProperties());
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/profile")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-shape-token")
                        .build()
        );

        assertThatThrownBy(() -> filter.filter(exchange, filtered -> ReactiveSecurityContextHolder
                .getContext().then()).block())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("configuration failure");
    }
}
