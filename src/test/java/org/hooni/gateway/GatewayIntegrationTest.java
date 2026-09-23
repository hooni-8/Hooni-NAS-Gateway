package org.hooni.gateway;

import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.util.Date;
import java.util.UUID;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/** 실제 보안 체인과 Gateway 라우팅을 임시 HTTP 서버까지 연결해 검증한다. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "application.security.max-request-size=2KB"
})
@AutoConfigureWebTestClient
class GatewayIntegrationTest {
    private static final KeyPair KEY_PAIR = generateKeyPair();
    private static final AtomicInteger CALLS = new AtomicInteger();
    private static final DisposableServer DOWNSTREAM = HttpServer.create().host("127.0.0.1").port(0)
            .handle((request, response) -> {
                CALLS.incrementAndGet();
                String cookie = request.requestHeaders().get("Cookie", "absent");
                String authorization = request.requestHeaders().get("Authorization", "absent");
                String requestId = request.requestHeaders().get("X-Request-ID", "absent");
                response.header("Echo-Cookie", cookie).header("Echo-Authorization", authorization)
                        .header("Echo-Request-ID", requestId);
                if (request.uri().startsWith("/auth/login")) {
                    response.addHeader("Set-Cookie", "accessToken=test-access; Path=/; HttpOnly; SameSite=Lax");
                    response.addHeader("Set-Cookie", "refreshToken=test-refresh; Path=/auth; HttpOnly; SameSite=Lax");
                }
                return response.send(request.receive().retain());
            }).bindNow();

    @DynamicPropertySource
    static void routes(DynamicPropertyRegistry properties) {
        properties.add("routers.defaults.auth-api.host", () -> "127.0.0.1");
        properties.add("routers.defaults.auth-api.port", DOWNSTREAM::port);
        properties.add("routers.defaults.template-api.host", () -> "127.0.0.1");
        properties.add("routers.defaults.template-api.port", DOWNSTREAM::port);
        properties.add("jwt.jwk-set-uri", () -> "");
        properties.add("jwt.public-key", () -> Base64.getEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded()));
    }

    @org.springframework.boot.test.web.server.LocalServerPort int port;
    WebTestClient client;

    @BeforeEach
    void connectToActualServer() {
        client = WebTestClient.bindToServer().baseUrl("http://127.0.0.1:" + port).build();
    }

    @AfterAll
    static void stopDownstream() { DOWNSTREAM.disposeNow(); }

    @Test
    void generalApiRemovesCookiesButRelaysAuthenticationAndRequestId() {
        String token = token();
        client.get().uri("/api/profile").cookie("accessToken", token)
                .cookie("refreshToken", "private-refresh")
                .exchange().expectStatus().isOk()
                .expectHeader().valueEquals("Echo-Cookie", "absent")
                .expectHeader().valueEquals("Echo-Authorization", "Bearer " + token)
                .expectBody().consumeWith(result -> assertThat(result.getResponseHeaders()
                        .getFirst("Echo-Request-ID")).isEqualTo(result.getResponseHeaders().getFirst("X-Request-ID")));
    }

    @Test
    void authApiKeepsCookiesWhenOriginIsAllowed() {
        client.post().uri("/auth/session").header("Origin", "http://localhost:3000")
                .cookie("refreshToken", "private-refresh").exchange().expectStatus().isOk()
                .expectHeader().value("Echo-Cookie", value -> assertThat(value).contains("refreshToken=private-refresh"));
    }

    @Test
    void authCookiesAndCredentialCorsHeadersReachFront() {
        client.post().uri("/auth/login").header("Origin", "http://localhost:3000")
                .bodyValue("{\"userId\":\"user01\",\"password\":\"password1\"}")
                .exchange().expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", "http://localhost:3000")
                .expectHeader().valueEquals("Access-Control-Allow-Credentials", "true")
                .expectHeader().valuesMatch(
                        "Set-Cookie",
                        ".*accessToken=test-access.*",
                        ".*refreshToken=test-refresh.*"
                );
    }

    @Test
    void missingOriginWithCookieIsRejectedBeforeDownstream() {
        int calls = CALLS.get();
        client.post().uri("/auth/refresh").cookie("refreshToken", "private-refresh")
                .exchange().expectStatus().isForbidden().expectBody()
                .jsonPath("$.code").isEqualTo("GATEWAY_403_ORIGIN");
        assertThat(CALLS.get()).isEqualTo(calls);
    }

    @Test
    void publicEndpointStillRequiresCorrectMethod() {
        client.get().uri("/auth/session").exchange().expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.code").isEqualTo("GATEWAY_401");
        client.get().uri("/actuator/health/readiness").exchange().expectStatus().isOk();
        client.get().uri("/actuator/health/extra").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void corsPreflightAllowsConfiguredHeadersOnly() {
        client.options().uri("/auth/login").header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "Content-Type")
                .exchange().expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", "http://localhost:3000");
        client.options().uri("/auth/login").header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "X-Unapproved")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void chunkedLimitRejectsBeforeDownstreamAndSmallBodyArrivesOnce() {
        int calls = CALLS.get();
        client.post().uri("/auth/session").body(Flux.just("x".repeat(1500), "y".repeat(1500)), String.class)
                .exchange().expectStatus().isEqualTo(413).expectBody()
                .jsonPath("$.code").isEqualTo("GATEWAY_413");
        assertThat(CALLS.get()).isEqualTo(calls);
        client.post().uri("/auth/session").body(Flux.just("hello", "world"), String.class)
                .exchange().expectStatus().isOk().expectBody(String.class).isEqualTo("helloworld");
        assertThat(CALLS.get()).isEqualTo(calls + 1);
    }

    private String token() {
        return Jwts.builder().id(UUID.randomUUID().toString()).subject("accessToken")
                .issuer("hooni-template-auth").claim("aud", "hooni-template-api")
                .claim("userCode", "test-user").claim("role", "ROLE_USER")
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(KEY_PAIR.getPrivate(), Jwts.SIG.RS256).compact();
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
