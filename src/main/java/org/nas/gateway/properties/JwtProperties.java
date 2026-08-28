package org.nas.gateway.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@Data
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secretKey;
    private Duration videoTokenValidity = Duration.ofHours(12);
}
