package org.hooni.gateway.filters.global;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.hooni.gateway.properties.AccessProperties;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.util.unit.DataSize;
import org.springframework.web.server.ServerWebExchange;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class RequestBodySizeFilterTest {

    @Test
    void rejectsDeclaredBodyLargerThanLimitBeforeCallingChain() {
        RequestBodySizeFilter filter = filterWithLimit(5);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/data")
                        .header(HttpHeaders.CONTENT_LENGTH, "6")
                        .build()
        );
        AtomicBoolean continued = new AtomicBoolean(false);

        filter.filter(exchange, ignored -> {
            continued.set(true);
            return reactor.core.publisher.Mono.empty();
        }).block();

        assertThat(continued).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
        assertThat(exchange.getResponse().getBodyAsString().block()).contains("GATEWAY_413");
    }

    @Test
    void rejectsChunkedBodyLargerThanLimitBeforeCallingChain() {
        RequestBodySizeFilter filter = filterWithLimit(5);
        ServerWebExchange exchange = chunkedExchange("123456");
        AtomicBoolean continued = new AtomicBoolean(false);
        assertThat(exchange.getRequest().getHeaders().getContentLength()).isEqualTo(-1);

        filter.filter(exchange, ignored -> {
            continued.set(true);
            return reactor.core.publisher.Mono.empty();
        }).block();

        assertThat(continued).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
    }

    @Test
    void buffersAndForwardsChunkedBodyWithinLimit() {
        RequestBodySizeFilter filter = filterWithLimit(10);
        ServerWebExchange exchange = chunkedExchange("123456");
        AtomicReference<String> forwardedBody = new AtomicReference<>();

        filter.filter(exchange, filtered -> DataBufferUtils.join(filtered.getRequest().getBody())
                .doOnNext(buffer -> {
                    byte[] bytes = new byte[buffer.readableByteCount()];
                    buffer.read(bytes);
                    forwardedBody.set(new String(bytes, StandardCharsets.UTF_8));
                    DataBufferUtils.release(buffer);
                })
                .then()).block();

        assertThat(forwardedBody.get()).isEqualTo("123456");
    }

    private RequestBodySizeFilter filterWithLimit(long bytes) {
        AccessProperties properties = new AccessProperties();
        properties.setMaxRequestSize(DataSize.ofBytes(bytes));
        return new RequestBodySizeFilter(
                properties,
                new org.hooni.gateway.common.response.GatewayErrorResponseWriter(new ObjectMapper())
        );
    }

    private ServerWebExchange chunkedExchange(String body) {
        MockServerHttpRequest source = MockServerHttpRequest.post("/api/data").body(body);
        ServerHttpRequest chunked = new ServerHttpRequestDecorator(source) {
            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(super.getHeaders());
                headers.remove(HttpHeaders.CONTENT_LENGTH);
                headers.set(HttpHeaders.TRANSFER_ENCODING, "chunked");
                return HttpHeaders.readOnlyHttpHeaders(headers);
            }
        };
        return MockServerWebExchange.from(source).mutate().request(chunked).build();
    }
}
