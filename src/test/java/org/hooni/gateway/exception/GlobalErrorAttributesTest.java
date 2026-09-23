package org.hooni.gateway.exception;

import org.junit.jupiter.api.Test;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.server.HandlerStrategies;
import org.springframework.web.reactive.function.server.ServerRequest;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalErrorAttributesTest {

    @Test
    void mapsConnectionFailureToBadGateway() {
        Map<String, Object> attributes = attributes(new RuntimeException(new ConnectException("refused")));

        assertThat(attributes.get("status")).isEqualTo(HttpStatus.BAD_GATEWAY.value());
        assertThat(attributes.get("message")).isEqualTo(HttpStatus.BAD_GATEWAY.getReasonPhrase());
    }

    @Test
    void mapsTimeoutToGatewayTimeout() {
        Map<String, Object> attributes = attributes(new RuntimeException(new SocketTimeoutException("timeout")));

        assertThat(attributes.get("status")).isEqualTo(HttpStatus.GATEWAY_TIMEOUT.value());
        assertThat(attributes.get("message")).isEqualTo(HttpStatus.GATEWAY_TIMEOUT.getReasonPhrase());
    }

    private Map<String, Object> attributes(Throwable error) {
        GlobalErrorAttributes errorAttributes = new GlobalErrorAttributes();
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/test").build()
        );
        errorAttributes.storeErrorInformation(error, exchange);
        ServerRequest request = ServerRequest.create(
                exchange,
                HandlerStrategies.withDefaults().messageReaders()
        );
        return errorAttributes.getErrorAttributes(request, ErrorAttributeOptions.defaults());
    }
}
