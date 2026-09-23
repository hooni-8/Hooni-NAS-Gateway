package org.hooni.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Gateway 애플리케이션 진입점이다.
 * 사용자/업무 DB를 조회하지 않고 JWT 검증과 하위 서비스 라우팅만 수행한다.
 */
// Auth API가 발급한 JWT만 사용하므로 Spring Boot의 임시 기본 사용자를 생성하지 않는다.
@SpringBootApplication(exclude = ReactiveUserDetailsServiceAutoConfiguration.class)
@ConfigurationPropertiesScan
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
