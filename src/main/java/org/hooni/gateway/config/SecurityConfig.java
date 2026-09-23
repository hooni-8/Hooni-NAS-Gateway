package org.hooni.gateway.config;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.hooni.gateway.filters.jwt.CustomJwtAuthenticationFilter;
import org.hooni.gateway.filters.jwt.JwtAccessDeniedHandler;
import org.hooni.gateway.filters.jwt.JwtAuthenticationEntryPoint;
import org.hooni.gateway.properties.AccessProperties;
import org.hooni.gateway.properties.CorsProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

/**
 * 공개 경로와 보호 경로를 구분하고 JWT 인증 필터, CORS, 401/403 응답을 구성한다.
 * 서버 세션과 기본 사용자 인증은 사용하지 않는다.
 */
@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomJwtAuthenticationFilter jwtFilter;
    private final JwtAuthenticationEntryPoint entryPoint;
    private final JwtAccessDeniedHandler accessDeniedHandler;
    private final AccessProperties accessProperties;
    private final CorsProperties corsProperties;

    @Bean
    /** 모든 비공개 요청이 JWT 인증을 통과하도록 구성하는 WebFlux 보안 체인이다. */
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {

        // 공개 경로는 라우팅/rewrite 이전의 Gateway 요청 경로를 기준으로 작성해야 한다.
        accessProperties.getPublicEndpoints().forEach(endpoint ->
                log.info("### Public endpoint: {} {}", endpoint.getMethod(), endpoint.getPath())
        );

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // 브라우저 인증 쿠키는 SameSite 정책을 전제로 한다.
                // 교차 사이트 쿠키를 허용하도록 변경하면 CSRF 방어도 함께 설계해야 한다.
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)

                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )

                .securityContextRepository(
                        // 인증 정보는 현재 요청의 Reactor Context에만 유지하고 서버 세션에는 저장하지 않는다.
                        NoOpServerSecurityContextRepository.getInstance()
                )

                .authorizeExchange(exchanges -> {
                    accessProperties.getPublicEndpoints().forEach(endpoint ->
                            exchanges.pathMatchers(endpoint.getMethod(), endpoint.getPath()).permitAll()
                    );
                    exchanges.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll();
                    exchanges.anyExchange().authenticated();
                })

                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }

    @Bean
    /** HttpOnly 인증 쿠키를 허용하기 위해 명시적인 Origin에만 credentials를 허용한다. */
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // 쿠키 인증을 사용하므로 credentials가 필요하다.
        // 이 경우 allowed-origin에는 "*"를 사용할 수 없고 명시적인 Origin만 등록해야 한다.
        config.setAllowCredentials(true);
        config.setAllowedOrigins(corsProperties.getAllowedOrigin());
        config.setAllowedMethods(corsProperties.getAllowedMethods());
        config.setAllowedHeaders(corsProperties.getAllowedHeaders());
        config.setExposedHeaders(corsProperties.getExposedHeaders());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", config);

        return source;
    }
}
