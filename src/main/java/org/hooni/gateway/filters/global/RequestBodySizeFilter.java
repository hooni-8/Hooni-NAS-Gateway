package org.hooni.gateway.filters.global;

import lombok.RequiredArgsConstructor;
import org.hooni.gateway.common.code.StatusCode;
import org.hooni.gateway.common.response.GatewayErrorResponseWriter;
import org.hooni.gateway.properties.AccessProperties;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.ByteArrayOutputStream;

/**
 * Content-Length 요청은 즉시 검사하고 길이를 알 수 없는 chunked 요청은 제한 크기까지만 버퍼링한다.
 * 크기를 초과한 본문은 하위 서비스에 일부라도 전달하기 전에 일관된 413 JSON으로 종료한다.
 */
@Component
@RequiredArgsConstructor
public class RequestBodySizeFilter implements WebFilter, Ordered {
    private final AccessProperties accessProperties;
    private final GatewayErrorResponseWriter errorResponseWriter;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        long maxBytes = accessProperties.getMaxRequestSize().toBytes();
        long contentLength = exchange.getRequest().getHeaders().getContentLength();

        if (contentLength > maxBytes) {
            return payloadTooLarge(exchange);
        }
        if (contentLength >= 0) {
            return chain.filter(exchange);
        }

        BodyAccumulator accumulator = new BodyAccumulator(Math.toIntExact(maxBytes));
        return exchange.getRequest().getBody()
                .handle((buffer, sink) -> {
                    try {
                        accumulator.append(buffer);
                    } catch (RequestBodyTooLargeException exception) {
                        sink.error(exception);
                    } finally {
                        DataBufferUtils.release(buffer);
                    }
                })
                .doOnDiscard(DataBuffer.class, DataBufferUtils::release)
                .then(Mono.defer(() -> {
                    if (accumulator.isEmpty()) {
                        return chain.filter(exchange);
                    }
                    return chain.filter(withBufferedBody(exchange, accumulator.toByteArray()));
                }))
                .onErrorResume(RequestBodyTooLargeException.class, ignored -> payloadTooLarge(exchange));
    }

    private ServerWebExchange withBufferedBody(ServerWebExchange exchange, byte[] body) {
        ServerHttpRequest decorated = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(super.getHeaders());
                headers.remove(HttpHeaders.TRANSFER_ENCODING);
                headers.setContentLength(body.length);
                return HttpHeaders.readOnlyHttpHeaders(headers);
            }

            @Override
            public Flux<DataBuffer> getBody() {
                // 구독되지 않는 요청에는 pooled buffer를 만들지 않는다. 재구독도 독립된 버퍼를 사용한다.
                return Flux.defer(() -> Flux.just(exchange.getResponse().bufferFactory().wrap(body)))
                        .doOnDiscard(DataBuffer.class, DataBufferUtils::release);
            }
        };
        return exchange.mutate().request(decorated).build();
    }

    private Mono<Void> payloadTooLarge(ServerWebExchange exchange) {
        return errorResponseWriter.write(
                exchange.getResponse(),
                HttpStatus.PAYLOAD_TOO_LARGE,
                StatusCode.PAYLOAD_TOO_LARGE
        );
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 15;
    }

    private static final class BodyAccumulator {
        private final int maxBytes;
        private final ByteArrayOutputStream output;

        private BodyAccumulator(int maxBytes) {
            this.maxBytes = maxBytes;
            this.output = new ByteArrayOutputStream(Math.min(maxBytes, 8192));
        }

        private void append(DataBuffer buffer) {
            int readableBytes = buffer.readableByteCount();
            if ((long) output.size() + readableBytes > maxBytes) {
                throw new RequestBodyTooLargeException();
            }
            byte[] bytes = new byte[readableBytes];
            buffer.read(bytes);
            output.write(bytes, 0, bytes.length);
        }

        private boolean isEmpty() {
            return output.size() == 0;
        }

        private byte[] toByteArray() {
            return output.toByteArray();
        }
    }

    private static final class RequestBodyTooLargeException extends RuntimeException {
    }
}
