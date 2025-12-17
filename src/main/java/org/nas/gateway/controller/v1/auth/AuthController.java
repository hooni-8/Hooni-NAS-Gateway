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

import java.util.Objects;

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
                    // 로그인 실패 판단 (code 값을 비교)
                    if (StatusCode.LOGIN_FAIL.getCode().equals(authResponse.getCode())) {
                        return ResponseEntity.ok(authResponse); // 실패 응답 반환
                    }

                    // 로그인 성공: Access Token을 쿠키로 보냄
                    ResponseCookie accessToken = ResponseCookie.from("accessToken", authResponse.getAccessToken())
                            .httpOnly(true)
                            .secure(false)
                            .path("/")
                            .sameSite("Strict")
                            .maxAge(60 * 60 * 24 * 7) // 7일 예시
                            .build();

                    return ResponseEntity.ok()
                            .header(HttpHeaders.SET_COOKIE, accessToken.toString())           // AccessToken Cookie에 저장
                            .body(AuthResponse.getSuccess());
                })
                .onErrorResume(e -> {
                    // 오류 발생 시 오류 응답 반환
                    log.info("Login failed: {}", e.getMessage());
                    return Mono.just(ResponseEntity.ok(AuthResponse.getError()));
                });
    }

    // refresh 토큰
    @PostMapping("/refresh")
    public Mono<ResponseEntity<AuthResponse>> refreshAccessToken(ServerHttpRequest request) {
        // Cookie에서 Refresh Token 읽기
        String refreshToken = request.getCookies().getFirst("refreshToken") != null
                ? Objects.requireNonNull(request.getCookies().getFirst("refreshToken")).getValue() : null;

        if (refreshToken == null) {
            return Mono.just(ResponseEntity.ok(AuthResponse.getLoginFail()));
        }

        String userCode = authService.getClaimsUserCode(refreshToken);
        String storedToken = refreshTokenService.getRefreshToken(userCode);

        if (storedToken == null || !storedToken.equals(refreshToken)) {
            return Mono.just(ResponseEntity.ok(AuthResponse.getLoginFail()));
        }

        // 새 Access Token 발급
        return authService.refreshToken(userCode)
                .map(ResponseEntity::ok)
                .onErrorResume(e -> Mono.just(ResponseEntity.ok(AuthResponse.getError())));
    }

    @PostMapping("/session")
    public Mono<ResponseEntity<LoginStatus>> getSession(ServerHttpRequest request) {

        HttpCookie accessToken = request.getCookies().getFirst("accessToken");

        if (accessToken == null) {
            return Mono.just(ResponseEntity.ok(LoginStatus.getError()));
        }

        String token = accessToken.getValue();

        log.info("token => {}", token);

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
                .sameSite("Strict")
                .maxAge(0)     // 즉시 만료
                .build();

        return Mono.just(
                ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, deleteAccessToken.toString())
                        .build()
        );

    }

}
