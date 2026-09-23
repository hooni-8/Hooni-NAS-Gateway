package org.hooni.gateway.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;

/** 실제 클라이언트 IP 계산에 사용할 신뢰 가능한 Ingress/Reverse Proxy 목록이다. */
@Data
@Validated
@ConfigurationProperties(prefix = "application.proxy")
public class ProxyProperties {
    /**
     * X-Forwarded-For를 추가하는 신뢰 가능한 프록시의 IP 또는 CIDR 목록.
     * 목록이 비어 있으면 전달 헤더를 신뢰하지 않고 직접 연결 주소만 사용한다.
     */
    @NotNull
    private List<@NotBlank String> trustedAddresses = new ArrayList<>();
}
