package org.nas.gateway.controller.v1.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nas.gateway.common.code.StatusCode;
import org.nas.gateway.common.model.LoginStatus;
import org.nas.gateway.model.v1.auth.request.LoginRequest;
import org.nas.gateway.model.v1.auth.request.RegisterExistsId;
import org.nas.gateway.model.v1.auth.request.RegisterRequest;
import org.nas.gateway.model.v1.auth.response.AuthResponse;
import org.nas.gateway.model.v1.common.response.CommonResponse;
import org.nas.gateway.service.v1.auth.AuthService;
import org.nas.gateway.service.v1.auth.RefreshTokenService;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
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

    // 회원가입
    @PostMapping("/register")
    public Mono<CommonResponse> register(@RequestBody RegisterRequest registerRequest) {
        log.info("Register: {}", registerRequest);

        return authService.register(registerRequest)
                .thenReturn(CommonResponse.getSuccess())
                .onErrorReturn(CommonResponse.getError());
    }

    // 아이디 중복 확인
    @PostMapping("/existsUserId")
    public Mono<Boolean> existsUserId(@RequestBody RegisterExistsId registerExistsId) {
        return authService.existsUserId(registerExistsId.getUserId());
    }

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
                            .secure(false) // 운영이면 true (HTTPS)
                            .path("/")
                            .sameSite("Lax")
                            .maxAge(Duration.ofMinutes(15))
                            .build();

                    // Refresh Token Cookie
                    ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", authResponse.getRefreshToken())
                            .httpOnly(true)
                            .secure(false)
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
            return Mono.just(ResponseEntity.ok(AuthResponse.getLoginFail()));
        }

        String userCode = authService.getClaimsUserCode(refreshToken);
        String storedToken = refreshTokenService.getRefreshToken(userCode);

        if (storedToken == null || !storedToken.equals(refreshToken)) {
            return Mono.just(ResponseEntity.ok(AuthResponse.getLoginFail()));
        }

        return authService.refreshToken(userCode)
                .map(newAccessToken -> {

                    ResponseCookie newAccessCookie = ResponseCookie.from("accessToken", newAccessToken.getAccessToken())
                            .httpOnly(true)
                            .secure(false)
                            .path("/")
                            .sameSite("Lax")
                            .maxAge(Duration.ofMinutes(15))
                            .build();

                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, newAccessCookie.toString())
                            .body(newAccessToken);
                })
                .onErrorResume(e -> Mono.just(ResponseEntity.ok(AuthResponse.getError())));
    }

    @PostMapping("/session")
    public Mono<ResponseEntity<LoginStatus>> getSession(ServerHttpRequest request) {

        HttpCookie accessToken = request.getCookies().getFirst("accessToken");

        if (accessToken == null) {
            return Mono.just(ResponseEntity.ok(LoginStatus.getError()));
        }

        String token = accessToken.getValue();

        return authService.getSession(token)
                .map(ResponseEntity::ok)
                .onErrorResume(e ->
                        Mono.just(ResponseEntity.ok(LoginStatus.getError()))
                );
    }

    // 로그아웃
    @PostMapping("/logout")
    public Mono<ResponseEntity<Void>> logout(ServerHttpRequest request) {

        HttpCookie accessToken = request.getCookies().getFirst("accessToken");

        if (accessToken != null) {
            String token = accessToken.getValue();
            String userCode = authService.getClaimsUserCode(token);
            refreshTokenService.deleteRefreshToken(userCode);
        }

        ResponseCookie deleteAccessToken = ResponseCookie.from("accessToken", "")
                .httpOnly(true)
                .secure(false)
                .path("/")
                .sameSite("Lax")
                .maxAge(0)     // 즉시 만료
                .build();

        return Mono.just(
                ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, deleteAccessToken.toString())
                        .build()
        );

    }

}
