package org.nas.gateway.filters.global;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
@ConditionalOnProperty(prefix = "application.response-wrapper", name = "enabled", havingValue = "true")
public class GlobalResponseWrapperFilter implements GlobalFilter, Ordered {

    private static final String SUCCESS_CODE = "0000";
    private static final String SUCCESS_MESSAGE = "SUCCESS";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpResponse originalResponse = exchange.getResponse();
        DataBufferFactory bufferFactory = originalResponse.bufferFactory();

        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {

                // Content-Type 체크
                MediaType contentType = getHeaders().getContentType();
                if (contentType == null || !isJson(contentType)) {
                    return super.writeWith(body);
                }

                // 에러 상태면 그대로 통과
                HttpStatusCode status = getStatusCode();
                if (status != null && status.isError()) {
                    return super.writeWith(body);
                }

                // JSON 전체를 모아서 한 번에 처리
                return DataBufferUtils.join(body)
                        .flatMap(dataBuffer -> {
                            byte[] content = new byte[dataBuffer.readableByteCount()];
                            dataBuffer.read(content);
                            DataBufferUtils.release(dataBuffer);

                            String originBody = new String(content, StandardCharsets.UTF_8);

                            // body가 비어있는 경우 방어
                            if (originBody.isBlank()) {
                                originBody = "null";
                            }
                            Object parsedBody;
                            try {
                                parsedBody = objectMapper.readValue(originBody, Object.class);
                            } catch (JsonProcessingException e) {
                                parsedBody = "null";
                            }

                            Map<String, Object> wrappedBody = Map.of(
                                    "code", SUCCESS_CODE,
                                    "message", SUCCESS_MESSAGE,
                                    "data", parsedBody
                            );

                            byte[] bytes;
                            try {
                                bytes = objectMapper.writeValueAsBytes(wrappedBody);
                            } catch (JsonProcessingException e) {
                                bytes = new byte[0];
                            }
                            DataBuffer buffer = bufferFactory.wrap(bytes);

                            return super.writeWith(Mono.just(buffer));
                        });
                }
            };

        return chain.filter(exchange.mutate().response(decoratedResponse).build());
    }

    private boolean isJson(MediaType mediaType) {
        return MediaType.APPLICATION_JSON.isCompatibleWith(mediaType)
                || (mediaType.getSubtype() != null && mediaType.getSubtype().endsWith("+json"));
    }

    /**
     * ErrorWebExceptionHandler(-1) 보다 뒤에서 실행
     */
    @Override
    public int getOrder() {
        return -10;
    }
}
