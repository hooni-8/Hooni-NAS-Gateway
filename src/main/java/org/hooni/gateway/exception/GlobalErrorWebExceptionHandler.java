package org.hooni.gateway.exception;

import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.*;
import org.hooni.gateway.common.response.GatewayErrorResponse;
import org.hooni.gateway.common.code.StatusCode;
import reactor.core.publisher.Mono;

import java.util.Map;

/** GlobalErrorAttributes를 공통 JSON 응답으로 직렬화하는 최종 WebFlux 오류 처리기다. */
public class GlobalErrorWebExceptionHandler extends AbstractErrorWebExceptionHandler {
    public GlobalErrorWebExceptionHandler(ErrorAttributes errorAttributes, WebProperties.Resources resources, ApplicationContext applicationContext) {
        super(errorAttributes, resources, applicationContext);
    }

    @Override
    protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {
        return RouterFunctions.route(RequestPredicates.all(), this::renderErrorResponse);
    }

    private Mono<ServerResponse> renderErrorResponse(ServerRequest request) {

        final Map<String, Object> errorPropertiesMap = getErrorAttributes(request, ErrorAttributeOptions.defaults());
        Object status = errorPropertiesMap.get("status");
        int statusCode = status instanceof Number number
                ? number.intValue()
                : HttpStatus.INTERNAL_SERVER_ERROR.value();

        return ServerResponse.status(statusCode)
                .contentType(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromValue(
                        GatewayErrorResponse.of(StatusCode.fromHttpStatus(statusCode))
                ));
    }
}
