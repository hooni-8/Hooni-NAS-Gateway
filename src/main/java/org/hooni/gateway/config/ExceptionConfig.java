package org.hooni.gateway.config;

import org.hooni.gateway.exception.GlobalErrorAttributes;
import org.hooni.gateway.exception.GlobalErrorWebExceptionHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.reactive.error.ErrorWebFluxAutoConfiguration;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.view.ViewResolver;

import java.util.stream.Collectors;

/**
 * Spring Boot 기본 WebFlux 오류 처리보다 먼저 공통 Gateway 오류 처리기를 등록한다.
 * 인증 필터가 직접 작성한 401/403 응답은 이 처리기를 거치지 않는다.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass(WebFluxConfigurer.class)
@AutoConfigureBefore(ErrorWebFluxAutoConfiguration.class)
public class ExceptionConfig {

    @Bean
    @Order(-1)
    ErrorWebExceptionHandler errorWebExceptionHandler(WebProperties webProperties, ApplicationContext applicationContext, ServerCodecConfigurer serverCodecConfigurer, ObjectProvider<ViewResolver> viewResolvers) {
        GlobalErrorWebExceptionHandler customErrorWebExceptionHandler = new GlobalErrorWebExceptionHandler(new GlobalErrorAttributes(), webProperties.getResources(), applicationContext);
        customErrorWebExceptionHandler.setViewResolvers(viewResolvers.orderedStream().collect(Collectors.toList()));
        customErrorWebExceptionHandler.setMessageWriters(serverCodecConfigurer.getWriters());
        customErrorWebExceptionHandler.setMessageReaders(serverCodecConfigurer.getReaders());

        return customErrorWebExceptionHandler;
    }
}
