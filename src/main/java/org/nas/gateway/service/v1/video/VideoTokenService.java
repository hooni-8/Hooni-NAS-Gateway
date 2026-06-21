package org.nas.gateway.service.v1.video;

import org.nas.gateway.model.v1.video.VideoTokenInfo;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class VideoTokenService {

    private final Map<String, VideoTokenInfo> tokenStore = new ConcurrentHashMap<>();

    public String createToken(String userCode, String fileId) {

        String token = UUID.randomUUID().toString();

        tokenStore.put(token,
                new VideoTokenInfo(
                        userCode,
                        fileId,
                        System.currentTimeMillis() + (1000 * 60 * 10)
                ));

        return token;
    }

    public VideoTokenInfo getTokenInfo(String token) {
        return tokenStore.get(token);
    }
}