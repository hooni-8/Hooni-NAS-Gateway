package org.hooni.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.hooni.gateway.common.router.RouterMapper;
import org.hooni.gateway.filters.routing.CustomTokenRelayGatewayFilterFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder.Builder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import lombok.RequiredArgsConstructor;

/**
 * routers 설정으로 Spring Cloud Gateway 라우트를 생성하고 모든 라우트에 Token Relay를 적용한다.
 * 이 계층은 하위 API를 호출할 뿐 DB나 회원 정보를 직접 조회하지 않는다.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class RouterConfig {

    @Value("${spring.webflux.base-path:}")
    String basePath;

    private final RouterMapper routerMapper;
    private final CustomTokenRelayGatewayFilterFactory customTokenRelayGatewayFilterFactory;

    /** 검증된 인증 정보를 하위 API 요청에 반영하는 공통 라우트 필터 목록이다. */
    List<GatewayFilter> getFilters(boolean forwardCookies) {
        List<GatewayFilter> filters = new ArrayList<>();

        // 검증된 인증 정보만 Authorization/x-authority 헤더로 하위 API에 전달한다.
        CustomTokenRelayGatewayFilterFactory.Config relayConfig =
                new CustomTokenRelayGatewayFilterFactory.Config();
        relayConfig.setForwardCookies(forwardCookies);
        filters.add(customTokenRelayGatewayFilterFactory.apply(relayConfig));

        return filters;
    }

    @Bean
    /** 애플리케이션 시작 시 설정된 모든 라우트를 검증하고 RouteLocator로 변환한다. */
    RouteLocator cloudRoutes(RouteLocatorBuilder builder) {
        Builder rb = builder.routes();
        log.info("RouterMapper loaded: {}", routerMapper.list().size());
        routerMapper.list().forEach((id, router) -> {
            String routeId = String.format("%s-router", id);
            router.validateRoute(routeId);
            String predicator = router.getContext();
            String destination = router.getRoutedUrl();
            String routeService = router.getUrl();
            String prefixPath = router.getPrefix();
            String rewriteTo = router.getRewrite();
            boolean isRemoveContext = router.isRemoveContext();

            String space1 = " ".repeat(Math.max(0, 30 - routeId.length()));
            String space2 = " ".repeat(Math.max(0, 15 - predicator.length()));
            String space3 = " ".repeat(Math.max(0, 20 - destination.length()));
            String contextPattern = Pattern.quote(predicator);

            log.info("[{}]{} FROM {}{} TO {}{} URL {}", routeId, space1, predicator, space2, destination, space3, router.getHost());

            rb.route(routeId, r -> r.path(predicator + "/**")
                    .filters(f -> {
                        // base-path를 사용하는 경우 가장 먼저 제거해야 이후 context rewrite가 정상 동작한다.
                        if (basePath != null && !basePath.isBlank()) {
                            f.rewritePath(Pattern.quote(basePath) + "/(?<segment>.*)", "/${segment}");
                        }

                        if (isRemoveContext) {
                            f.rewritePath(contextPattern + "/(?<segment>.*)", "/${segment}");
                        } else {
                            if(rewriteTo != null && !rewriteTo.isBlank()) {
                                // 지정된 context로 rewrite
                                f.rewritePath(contextPattern + "/(?<segment>.*)", rewriteTo + "/${segment}");
                            }

                            if(prefixPath != null && !prefixPath.isBlank()) {
                                // 지정된 context 앞으로 prefix 추가
                                f.prefixPath(prefixPath);
                            }
                        }
                        // 모든 외부 라우트에 토큰 전달 및 신뢰 헤더 정제를 강제한다.
                        return f.filters(getFilters(router.isForwardCookies()));
                    }).uri(routeService));
        });

        return rb.build();
    }
}
