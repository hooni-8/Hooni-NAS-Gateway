package org.nas.gateway.controller.v1.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nas.gateway.common.code.StatusCode;
import org.nas.gateway.common.model.LoginStatus;
import org.nas.gateway.model.v1.auth.request.LoginRequest;
import org.nas.gateway.model.v1.auth.response.AuthResponse;
import org.nas.gateway.model.v1.common.response.CommonResponse;
import org.nas.gateway.service.v1.auth.AuthService;
import org.nas.gateway.service.v1.auth.RefreshTokenService;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    private final RefreshTokenService refreshTokenService;

    @Value("${application.cookie.secure:false}")
    private boolean secureCookie;

    // 로그인
    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest)
                .map(authResponse -> {

                    // 로그인 실패
                    if (StatusCode.LOGIN_FAIL.getCode().equals(authResponse.getCode())) {
                        return ResponseEntity.ok(authResponse);
                    }

                    // Access Token Cookie
                    ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken", authResponse.getAccessToken())
                            .httpOnly(true)
                            .secure(secureCookie)
                            .path("/")
                            .sameSite("Lax")
                            .maxAge(Duration.ofMinutes(15))
                            .build();

                    // Refresh Token Cookie
                    ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", authResponse.getRefreshToken())
                            .httpOnly(true)
                            .secure(secureCookie)
                            .path("/auth/refresh")
                            .sameSite("Lax")
                            .maxAge(Duration.ofDays(7))
                            .build();

                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())
                            .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                            .body(AuthResponse.getSuccess());
                })
                .onErrorResume(e -> {
                    log.info("Login failed: {}", e.getMessage());
                    return Mono.just(ResponseEntity.ok(AuthResponse.getError()));
                });
    }

    // refresh 토큰
    @PostMapping("/refresh")
    public Mono<ResponseEntity<AuthResponse>> refreshAccessToken(ServerHttpRequest request) {

        String refreshToken = request.getCookies()
                .getFirst("refreshToken") != null
                ? request.getCookies().getFirst("refreshToken").getValue()
                : null;

        if (refreshToken == null) {
            return Mono.just(refreshUnauthorizedResponse());
        }

        String userCode;
        try {
            userCode = authService.getRefreshTokenUserCode(refreshToken);
        } catch (Exception e) {
            return Mono.just(refreshUnauthorizedResponse());
        }

        String storedToken = refreshTokenService.getRefreshToken(userCode);

        if (storedToken == null || !storedToken.equals(refreshToken)) {
            return Mono.just(refreshUnauthorizedResponse());
        }

        return authService.refreshToken(userCode)
                .map(newAccessToken -> {

                    ResponseCookie newAccessCookie = ResponseCookie.from("accessToken", newAccessToken.getAccessToken())
                            .httpOnly(true)
                            .secure(secureCookie)
                            .path("/")
                            .sameSite("Lax")
                            .maxAge(Duration.ofMinutes(15))
                            .build();

                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, newAccessCookie.toString())
                            // access token은 HttpOnly 쿠키로만 전달한다.
                            .body(AuthResponse.getSuccess());
                })
                .switchIfEmpty(Mono.just(refreshUnauthorizedResponse()))
                .onErrorResume(e -> Mono.just(refreshUnauthorizedResponse()));
    }

    @PostMapping("/session")
    public Mono<ResponseEntity<LoginStatus>> getSession(ServerHttpRequest request) {

        HttpCookie accessToken = request.getCookies().getFirst("accessToken");

        if (accessToken == null) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(LoginStatus.getError()));
        }

        String token = accessToken.getValue();

        return authService.getSession(token)
                .map(ResponseEntity::ok)
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(LoginStatus.getError()))
                );
    }

    private ResponseEntity<AuthResponse> refreshUnauthorizedResponse() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponse.getLoginFail());
    }

    // 로그아웃
    @PostMapping("/logout")
    public Mono<ResponseEntity<Void>> logout(ServerHttpRequest request) {

        HttpCookie accessToken = request.getCookies().getFirst("accessToken");
        HttpCookie refreshToken = request.getCookies().getFirst("refreshToken");

        // access token이 만료됐어도 브라우저 쿠키는 반드시 지워야 한다.
        // refresh token을 우선 사용해 Redis의 세션을 폐기하고, 실패해도 로그아웃 응답은 계속한다.
        String userCode = extractRefreshTokenUserCode(refreshToken);
        if (userCode == null) {
            userCode = extractAccessTokenUserCode(accessToken);
        }

        if (userCode != null) {
            try {
                refreshTokenService.deleteRefreshToken(userCode);
            } catch (Exception e) {
                log.warn("Failed to revoke refresh token during logout");
            }
        }

        ResponseCookie deleteAccessToken = ResponseCookie.from("accessToken", "")
                .httpOnly(true)
                .secure(secureCookie)
                .path("/")
                .sameSite("Lax")
                .maxAge(0)     // 즉시 만료
                .build();

        ResponseCookie deleteRefreshToken = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(secureCookie)
                .path("/auth/refresh")
                .sameSite("Lax")
                .maxAge(0)
                .build();

        return Mono.just(ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, deleteAccessToken.toString())
                .header(HttpHeaders.SET_COOKIE, deleteRefreshToken.toString())
                .build());

    }

    private String extractRefreshTokenUserCode(HttpCookie tokenCookie) {
        if (tokenCookie == null || tokenCookie.getValue().isBlank()) {
            return null;
        }

        try {
            return authService.getRefreshTokenUserCode(tokenCookie.getValue());
        } catch (Exception e) {
            return null;
        }
    }

    private String extractAccessTokenUserCode(HttpCookie tokenCookie) {
        if (tokenCookie == null || tokenCookie.getValue().isBlank()) {
            return null;
        }

        try {
            return authService.getClaimsUserCode(tokenCookie.getValue());
        } catch (Exception e) {
            return null;
        }
    }

}
