package org.nas.gateway.controller.v1.video;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.nas.gateway.entity.user.UserDetail;
import org.nas.gateway.filters.jwt.JwtTokenProvider;
import org.nas.gateway.service.v1.auth.AuthService;
import org.nas.gateway.service.v1.video.VideoTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/video-entry")
@RequiredArgsConstructor
public class VideoController {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private final AuthService authService;

    @GetMapping("/{fileId}")
    public Mono<Map<String, String>> getVideoUrl(
            ServerHttpRequest request,
            @PathVariable String fileId) {

        HttpCookie accessToken = request.getCookies().getFirst("accessToken");

        if (accessToken == null) {
            return Mono.just(Map.of("url", ""));
        }

        String token = accessToken.getValue();
        String userCode = authService.getClaimsUserCode(token);

        return authService.userDetailsFindByUserCode(userCode)
                .map(jwtTokenProvider::generateVideoToken)
                .map(videoToken ->
                        Map.of("url",
                                "/nas/api/v1/file/video/" +
                                        fileId +
                                        "?stToken=" +
                                        URLEncoder.encode(videoToken, StandardCharsets.UTF_8)));
    }
}
