package org.hooni.gateway.common.response;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.hooni.gateway.common.code.StatusCode;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * WebFlux 필터처럼 MVC 예외 처리기를 거치지 않는 위치에서 JSON 오류 응답을 작성한다.
 * 이미 응답이 전송된 경우에는 본문을 다시 쓰지 않는다.
 */
@Component
@RequiredArgsConstructor
public class GatewayErrorResponseWriter {

    private final ObjectMapper objectMapper;

    public Mono<Void> write(ServerHttpResponse response, HttpStatus status, StatusCode statusCode) {
        if (response.isCommitted()) {
            return response.setComplete();
        }

        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        byte[] body = toJson(statusCode);
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }

    private byte[] toJson(StatusCode statusCode) {
        try {
            return objectMapper.writeValueAsBytes(GatewayErrorResponse.of(statusCode));
        } catch (JsonProcessingException exception) {
            return "{\"code\":\"GATEWAY_9999\",\"message\":\"ERROR\",\"data\":null}"
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
    }
}
