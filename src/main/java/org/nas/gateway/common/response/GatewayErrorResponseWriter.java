package org.nas.gateway.common.response;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class GatewayErrorResponseWriter {

    private final ObjectMapper objectMapper;

    public Mono<Void> write(ServerHttpResponse response, HttpStatus status, String message) {
        if (response.isCommitted()) {
            return response.setComplete();
        }

        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        byte[] body = toJson(message);
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }

    private byte[] toJson(String message) {
        try {
            return objectMapper.writeValueAsBytes(GatewayErrorResponse.of(message));
        } catch (JsonProcessingException exception) {
            return "{\"code\":\"9999\",\"message\":\"ERROR\",\"data\":null}".getBytes();
        }
    }
}
