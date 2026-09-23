package org.hooni.gateway.common.router;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.hooni.gateway.properties.RouterProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Map;
import java.util.LinkedHashMap;

/** application 설정의 라우트 목록을 선언 순서대로 바인딩한다. */
@Data
@Validated
@ConfigurationProperties(prefix = "routers")
public class RouterMapper {

    @NotEmpty
    private Map<@NotBlank String, @Valid RouterProperties> defaults = new LinkedHashMap<>();

    public Map<String, RouterProperties> list() {
        return this.defaults;
    }
}
